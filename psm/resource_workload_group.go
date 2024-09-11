package psm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceWorkloadGroup() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceWorkloadGroupCreate,
		ReadContext:   resourceWorkloadGroupRead,
		UpdateContext: resourceWorkloadGroupUpdate,
		DeleteContext: resourceWorkloadGroupDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"workload_selector": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: false,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"workload_label_selector": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"workload_label_key": {
										Type:     schema.TypeString,
										Required: true,
									},
									"operator": {
										Type:     schema.TypeString,
										Required: true,
									},
									"values": {
										Type:     schema.TypeList,
										Elem:     &schema.Schema{Type: schema.TypeString},
										Required: true,
									},
								},
							},
						},
					},
				},
			},
			"ip_collections": {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
				ForceNew: false,
			},
		},
	}
}

type WorkloadGroup struct {
	Kind       interface{} `json:"kind"`
	APIVersion interface{} `json:"api-version"`
	Meta       struct {
		Name            string      `json:"name"`
		Tenant          interface{} `json:"tenant"`
		Namespace       interface{} `json:"namespace"`
		GenerationID    interface{} `json:"generation-id"`
		ResourceVersion interface{} `json:"resource-version"`
		UUID            interface{} `json:"uuid"`
		Labels          interface{} `json:"labels"`
		SelfLink        interface{} `json:"self-link"`
		DisplayName     interface{} `json:"display-name"`
	} `json:"meta"`

	Spec struct {
		WorkloadSelector []WorkloadSelector `json:"workload-selector"`
		IpCollections    []string           `json:"ip-collections"`
	} `json:"spec"`
}

type Requirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

type WorkloadSelector struct {
	Requirements []Requirement `json:"requirements"`
}

func convertInterfaceToStringSlice(i interface{}) []string {
	slice := i.([]interface{})
	strSlice := make([]string, len(slice))
	for i, v := range slice {
		strSlice[i] = v.(string)
	}
	return strSlice
}

func resourceWorkloadGroupCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	// Create a new WorkloadGroup instance and populate required fields
	workloadgroup := &WorkloadGroup{}
	workloadgroup.Meta.Name = d.Get("name").(string)

	workloadSelector := make([]WorkloadSelector, 0)
	for _, ws := range d.Get("workload_selector").([]interface{}) {
		wsMap := ws.(map[string]interface{})
		requirements := make([]Requirement, 0)
		for _, req := range wsMap["workload_label_selector"].([]interface{}) {
			reqMap := req.(map[string]interface{})
			requirement := Requirement{
				Key:      reqMap["workload_label_key"].(string),
				Operator: reqMap["operator"].(string),
				Values:   convertInterfaceToStringSlice(reqMap["values"]),
			}
			requirements = append(requirements, requirement)
		}
		workloadSelector = append(workloadSelector, WorkloadSelector{
			Requirements: requirements,
		})
	}
	workloadgroup.Spec.WorkloadSelector = workloadSelector

	if v, ok := d.GetOk("ip_collections"); ok {
		workloadgroup.Spec.IpCollections = convertInterfaceToStringSlice(v)
	}

	jsonBytes, err := json.Marshal(workloadgroup)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", config.Server+"/configs/workload/v1/tenant/default/workloadgroups", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	// Log the request details
	log.Printf("[DEBUG] Request method: %s", req.Method)
	log.Printf("[DEBUG] Request URL: %s", req.URL.String())
	log.Printf("[DEBUG] Request body: %s", jsonBytes)

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("failed to create workload: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "Workload creation failed",
				Detail:   errMsg,
			},
		}
	}

	responseBody := &Workload{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responseBody.Meta.UUID.(string))

	return append(diag.Diagnostics{}, resourceWorkloadGroupRead(ctx, d, m)...)
}

func resourceWorkloadGroupRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/workload/v1/tenant/default/workloadgroups/" + d.Get("name").(string)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to read workload group: HTTP %s", resp.Status)
	}

	workloadgroup := &WorkloadGroup{}
	if err := json.NewDecoder(resp.Body).Decode(workloadgroup); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", workloadgroup.Meta.Name)
	if len(workloadgroup.Spec.WorkloadSelector) > 0 && len(workloadgroup.Spec.WorkloadSelector[0].Requirements) > 0 {
		d.Set("workload_label_selector", workloadgroup.Spec.WorkloadSelector[0].Requirements)
	}
	d.Set("ip_collections", workloadgroup.Spec.IpCollections)

	return nil
}

func resourceWorkloadGroupUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	// Create a new WorkloadGroup instance and populate required fields
	workloadgroup := &WorkloadGroup{}
	workloadgroup.Meta.Name = d.Get("name").(string)

	workloadSelector := make([]WorkloadSelector, 0)
	for _, ws := range d.Get("workload_selector").([]interface{}) {
		wsMap := ws.(map[string]interface{})
		requirements := make([]Requirement, 0)
		for _, req := range wsMap["workload_label_selector"].([]interface{}) {
			reqMap := req.(map[string]interface{})
			requirement := Requirement{
				Key:      reqMap["workload_label_key"].(string),
				Operator: reqMap["operator"].(string),
				Values:   convertInterfaceToStringSlice(reqMap["values"]),
			}
			requirements = append(requirements, requirement)
		}
		workloadSelector = append(workloadSelector, WorkloadSelector{
			Requirements: requirements,
		})
	}
	workloadgroup.Spec.WorkloadSelector = workloadSelector

	if v, ok := d.GetOk("ip_collections"); ok {
		workloadgroup.Spec.IpCollections = convertInterfaceToStringSlice(v)
	}

	jsonBytes, err := json.Marshal(workloadgroup)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", config.Server+"/configs/workload/v1/tenant/default/workloadgroups/"+workloadgroup.Meta.Name, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	// Log the request details
	log.Printf("[DEBUG] Request method: %s", req.Method)
	log.Printf("[DEBUG] Request URL: %s", req.URL.String())
	log.Printf("[DEBUG] Request body: %s", jsonBytes)

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("failed to update workload: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "Workload update failed",
				Detail:   errMsg,
			},
		}
	}

	return resourceWorkloadGroupRead(ctx, d, m)
}

func resourceWorkloadGroupDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/workload/v1/tenant/default/workloadgroups/" + d.Get("name").(string)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return diag.Errorf("failed to delete workload: HTTP %s", resp.Status)
	}

	d.SetId("")

	return nil
}
