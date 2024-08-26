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

func resourceFlowExportPolicy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceFlowExportPolicyCreate,
		ReadContext:   resourceFlowExportPolicyRead,
		UpdateContext: resourceFlowExportPolicyUpdate,
		DeleteContext: resourceFlowExportPolicyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceFlowExportPolicyImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"interval": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: false,
			},
			"format": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: false,
			},
			"target": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"destination": {
							Type:     schema.TypeString,
							Required: true,
						},
						"transport": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
		},
	}
}

type FlowExportPolicy struct {
	Kind       interface{} `json:"kind"`
	APIVersion interface{} `json:"api-version"`
	Meta       struct {
		Name            string      `json:"name"`
		Tenant          string      `json:"tenant"`
		Namespace       interface{} `json:"namespace"`
		GenerationID    interface{} `json:"generation-id"`
		ResourceVersion interface{} `json:"resource-version"`
		UUID            interface{} `json:"uuid"`
		Labels          interface{} `json:"labels"`
		SelfLink        interface{} `json:"self-link"`
		DisplayName     interface{} `json:"display-name"`
	} `json:"meta"`
	Spec struct {
		Interval         string `json:"interval"`
		TemplateInterval string `json:"template-interval"`
		Format           string `json:"format"`
		Exports          []struct {
			Destination   string      `json:"destination"`
			Gateway       interface{} `json:"gateway"`
			Transport     string      `json:"transport"`
			VirtualRouter interface{} `json:"virtual-router"`
		} `json:"exports"`
		Disabled interface{} `json:"disabled"`
	} `json:"spec"`
}

func resourceFlowExportPolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	ipfix := &FlowExportPolicy{}
	ipfix.Meta.Name = d.Get("name").(string)
	ipfix.Meta.Tenant = "default"
	ipfix.Spec.Interval = d.Get("interval").(string)
	ipfix.Spec.Format = d.Get("format").(string)
	exports := d.Get("target").([]interface{})
	for _, v := range exports {
		exportMap := v.(map[string]interface{})
		export := struct {
			Destination   string      `json:"destination"`
			Gateway       interface{} `json:"gateway"`
			Transport     string      `json:"transport"`
			VirtualRouter interface{} `json:"virtual-router"`
		}{
			Destination: exportMap["destination"].(string),
			Transport:   exportMap["transport"].(string),
		}
		ipfix.Spec.Exports = append(ipfix.Spec.Exports, export)
	}

	jsonBytes, err := json.Marshal(ipfix)
	if err != nil {
		log.Printf("[ERROR] Error marshalling IPFIX: %s", err)
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Creating IPFIX with name: %s", ipfix.Meta.Name)

	req, err := http.NewRequestWithContext(ctx, "POST", config.Server+"/configs/monitoring/v1/tenant/default/flowExportPolicy", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when creating IPFIX: %s", err)
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("failed to create IPFIX: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "IPFIX creation failed",
				Detail:   errMsg,
			},
		}
	}

	responseBody := &FlowExportPolicy{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responseBody.Meta.UUID.(string))

	log.Printf("[DEBUG] IPFIX created with UUID: %s", responseBody.Meta.UUID.(string))

	return append(diag.Diagnostics{}, resourceFlowExportPolicyRead(ctx, d, m)...)
}

func resourceFlowExportPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/monitoring/v1/tenant/default/flowExportPolicy/" + d.Get("name").(string)
	log.Printf("[DEBUG] Reading FlowExportPolicy with name: %s", d.Get("name").(string))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when reading FlowExportPolicy: %s", err)
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to read FlowExportPolicy: HTTP %s", resp.Status)
	}

	flowExportPolicy := &FlowExportPolicy{}
	if err := json.NewDecoder(resp.Body).Decode(flowExportPolicy); err != nil {
		return diag.FromErr(err)
	}

	// Set the properties from the response
	d.Set("name", flowExportPolicy.Meta.Name)
	d.Set("interval", flowExportPolicy.Spec.Interval)
	d.Set("format", flowExportPolicy.Spec.Format)
	exports := make([]map[string]interface{}, len(flowExportPolicy.Spec.Exports))
	for i, export := range flowExportPolicy.Spec.Exports {
		exports[i] = map[string]interface{}{
			"destination": export.Destination,
			"transport":   export.Transport,
		}
	}
	d.Set("exports", exports)

	return nil
}

func resourceFlowExportPolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	ipfix := &FlowExportPolicy{}
	ipfix.Meta.Name = d.Get("name").(string)
	ipfix.Meta.Tenant = "default"
	ipfix.Spec.Interval = d.Get("interval").(string)
	ipfix.Spec.Format = d.Get("format").(string)
	exports := d.Get("target").([]interface{})
	for _, v := range exports {
		exportMap := v.(map[string]interface{})
		export := struct {
			Destination   string      `json:"destination"`
			Gateway       interface{} `json:"gateway"`
			Transport     string      `json:"transport"`
			VirtualRouter interface{} `json:"virtual-router"`
		}{
			Destination: exportMap["destination"].(string),
			Transport:   exportMap["transport"].(string),
		}
		ipfix.Spec.Exports = append(ipfix.Spec.Exports, export)
	}

	jsonBytes, err := json.Marshal(ipfix)
	if err != nil {
		log.Printf("[ERROR] Error marshalling IPFIX: %s", err)
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Updating IPFIX with name: %s", ipfix.Meta.Name)

	req, err := http.NewRequestWithContext(ctx, "PUT", config.Server+"/configs/monitoring/v1/tenant/default/flowExportPolicy/"+ipfix.Meta.Name, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when updating IPFIX: %s", err)
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("failed to update IPFIX: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "IPFIX update failed",
				Detail:   errMsg,
			},
		}
	}

	responseBody := &FlowExportPolicy{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responseBody.Meta.UUID.(string))

	log.Printf("[DEBUG] IPFIX updated with UUID: %s", responseBody.Meta.UUID.(string))

	return append(diag.Diagnostics{}, resourceFlowExportPolicyRead(ctx, d, m)...)
}

func resourceFlowExportPolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/monitoring/v1/tenant/default/flowExportPolicy/" + d.Get("name").(string)

	log.Printf("[DEBUG] Deleting FlowExportPolicy with name: %s", d.Get("name").(string))

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when deleting FlowExportPolicy: %s", err)
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to delete FlowExportPolicy: HTTP %s", resp.Status)
	}

	d.SetId("")

	return nil
}

func resourceFlowExportPolicyImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	config := m.(*Config)
	client := config.Client()

	name := d.Id()

	url := fmt.Sprintf("%s/configs/monitoring/v1/tenant/default/flowExportPolicy/%s", config.Server, name)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %s", err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error reading FlowExportPolicy: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to read FlowExportPolicy: HTTP %s", resp.Status)
	}

	flowExportPolicy := &FlowExportPolicy{}
	if err := json.NewDecoder(resp.Body).Decode(flowExportPolicy); err != nil {
		return nil, fmt.Errorf("error decoding response: %s", err)
	}

	d.SetId(flowExportPolicy.Meta.UUID.(string))
	d.Set("name", flowExportPolicy.Meta.Name)
	d.Set("interval", flowExportPolicy.Spec.Interval)
	d.Set("format", flowExportPolicy.Spec.Format)

	exports := make([]map[string]interface{}, len(flowExportPolicy.Spec.Exports))
	for i, export := range flowExportPolicy.Spec.Exports {
		exports[i] = map[string]interface{}{
			"destination": export.Destination,
			"transport":   export.Transport,
		}
	}
	d.Set("target", exports)

	return []*schema.ResourceData{d}, nil
}
