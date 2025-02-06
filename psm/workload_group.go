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
		UUID            string      `json:"uuid"`
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

type PolicyList struct {
	Items []PolicyListItem `json:"items"`
}

type PolicyListItem struct {
	Meta struct {
		Name        string      `json:"name"`
		DisplayName interface{} `json:"display-name"`
	} `json:"meta"`
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

	responseBody := &WorkloadGroup{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responseBody.Meta.UUID)

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
	workloadName := d.Get("name").(string)

	// First, remove this workload group from all security policies
	if err := removeWorkloadGroupFromPolicies(ctx, client, config, workloadName); err != nil {
		return diag.FromErr(err)
	}

	// Then delete the workload group itself
	url := config.Server + "/configs/workload/v1/tenant/default/workloadgroups/" + workloadName
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

func removeWorkloadGroupFromPolicies(ctx context.Context, client *http.Client, config *Config, workloadName string) error {
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/configs/security/v1/tenant/default/networksecuritypolicies", config.Server), nil)
	if err != nil {
		return err
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var policyList PolicyList
	if err := json.NewDecoder(resp.Body).Decode(&policyList); err != nil {
		return err
	}

	for _, item := range policyList.Items {
		if err := updatePolicyWorkloadGroups(ctx, client, config, item.Meta.Name, workloadName); err != nil {
			return err
		}
	}

	return nil
}

func updatePolicyWorkloadGroups(ctx context.Context, client *http.Client, config *Config, policyName, workloadName string) error {
	// Get current policy
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/configs/security/v1/tenant/default/networksecuritypolicies/%s", config.Server, policyName), nil)
	if err != nil {
		return err
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	var policy NetworkSecurityPolicy
	if err := json.Unmarshal(bodyBytes, &policy); err != nil {
		return fmt.Errorf("failed to decode policy: %v", err)
	}

	// Store original metadata
	originalKind := policy.Kind
	originalAPIVersion := policy.APIVersion
	originalMeta := policy.Meta
	originalStatus := policy.Status

	// Update rules
	modified := false
	newRules := make([]Rule, 0)
	for _, rule := range policy.Spec.Rules {
		if containsString(rule.FromWorkloadGroup, workloadName) || containsString(rule.ToWorkloadGroup, workloadName) {
			modified = true
			// Skip rules that would only reference the workload group being removed
			if len(rule.ToWorkloadGroup) == 1 && rule.ToWorkloadGroup[0] == workloadName &&
				len(rule.ToIPAddresses) == 0 && len(rule.ToIPCollections) == 0 {
				continue
			}
			// Remove workload group references
			rule.FromWorkloadGroup = removeString(rule.FromWorkloadGroup, workloadName)
			rule.ToWorkloadGroup = removeString(rule.ToWorkloadGroup, workloadName)
		}
		newRules = append(newRules, rule)
	}

	if !modified {
		return nil
	}

	policy.Spec.Rules = newRules

	// Restore original metadata
	policy.Kind = originalKind
	policy.APIVersion = originalAPIVersion
	policy.Meta = originalMeta
	policy.Status = originalStatus

	// Update policy
	jsonBytes, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal updated policy: %v", err)
	}

	req, err = http.NewRequestWithContext(ctx, "PUT",
		fmt.Sprintf("%s/configs/security/v1/tenant/default/networksecuritypolicies/%s", config.Server, policyName),
		bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		responseBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update policy: HTTP %d %s: %s", resp.StatusCode, resp.Status, string(responseBody))
	}

	return nil
}

func removeString(slice []string, str string) []string {
	newSlice := make([]string, 0)
	for _, s := range slice {
		if s != str {
			newSlice = append(newSlice, s)
		}
	}
	return newSlice
}
