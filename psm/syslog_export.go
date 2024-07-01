package psm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceSyslogPolicy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceSyslogPolicyCreate,
		ReadContext:   resourceSyslogPolicyRead,
		UpdateContext: resourceSyslogPolicyUpdate,
		DeleteContext: resourceSyslogPolicyDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"format": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: false,
			},
			"filter": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"syslogconfig": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"facility": {
							Type:     schema.TypeString,
							Required: true,
							ForceNew: false,
						},
						"disable_batching": {
							Type:     schema.TypeBool,
							Required: true,
							ForceNew: false,
						},
					},
				},
			},
			"psm_target": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enable": {
							Type:     schema.TypeBool,
							Required: true,
						},
					},
				},
			},
			"targets": {
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

type SyslogPolicy struct {
	Meta struct {
		Name   string `json:"name"`
		Tenant string `json:"tenant"`
		UUID   string `json:"uuid"`
	} `json:"meta"`
	Spec struct {
		Format    string       `json:"format"`
		Filter    []string     `json:"filter"`
		Config    SyslogConfig `json:"config"`
		PsmTarget PsmTarget    `json:"psm-target"`
		Targets   []Target     `json:"targets"`
	} `json:"spec"`
}

type SyslogConfig struct {
	FacilityOverride string `json:"facility-override"`
	DisableBatching  bool   `json:"disable-batching"`
}

type PsmTarget struct {
	Enable bool `json:"enable"`
}

type Target struct {
	Destination string `json:"destination"`
	Transport   string `json:"transport"`
}

func resourceSyslogPolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	syslogPolicy := &SyslogPolicy{}
	syslogPolicy.Meta.Name = d.Get("name").(string)
	syslogPolicy.Meta.Tenant = "default"
	syslogPolicy.Spec.Format = d.Get("format").(string)

	psmTarget := d.Get("psm_target").([]interface{})[0].(map[string]interface{})
	syslogPolicy.Spec.PsmTarget = PsmTarget{
		Enable: psmTarget["enable"].(bool),
	}

	filterInterface := d.Get("filter").([]interface{})
	filterStrings := make([]string, len(filterInterface))
	for i, v := range filterInterface {
		if v != nil {
			filterStrings[i] = v.(string)
		}
	}

	syslogConfig := d.Get("syslogconfig").([]interface{})[0].(map[string]interface{})
	syslogPolicy.Spec.Config = SyslogConfig{
		FacilityOverride: syslogConfig["facility"].(string),
		DisableBatching:  syslogConfig["disable_batching"].(bool),
	}

	syslogPolicy.Spec.Filter = filterStrings

	targets := d.Get("targets").([]interface{})
	for _, t := range targets {
		target := t.(map[string]interface{})
		syslogPolicy.Spec.Targets = append(syslogPolicy.Spec.Targets, Target{
			Destination: target["destination"].(string),
			Transport:   target["transport"].(string),
		})
	}

	jsonBytes, err := json.Marshal(syslogPolicy)
	if err != nil {
		log.Printf("[ERROR] Error marshalling Syslog Policy: %s", err)
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Creating Syslog Policy with name: %s", syslogPolicy.Meta.Name)

	req, err := http.NewRequestWithContext(ctx, "POST", config.Server+"/configs/monitoring/v1/tenant/default/fwlogPolicy", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when creating Syslog Policy: %s", err)
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("failed to create Syslog Policy: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "Syslog Policy creation failed",
				Detail:   errMsg,
			},
		}
	}

	responseBody := &SyslogPolicy{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responseBody.Meta.UUID)

	log.Printf("[DEBUG] Syslog Policy created with UUID: %s", responseBody.Meta.UUID)
	// Log the request details
	log.Printf("[DEBUG] Request method: %s", req.Method)
	log.Printf("[DEBUG] Request URL: %s", req.URL.String())
	log.Printf("[DEBUG] Request body: %s", jsonBytes)

	return resourceSyslogPolicyRead(ctx, d, m)
}

func resourceSyslogPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	fwlogPolicyName := d.Get("name").(string)
	req, err := http.NewRequestWithContext(ctx, "GET", config.Server+"/configs/monitoring/v1/tenant/default/fwlogPolicy/"+fwlogPolicyName, nil)
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when reading Syslog Policy: %s", err)
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("failed to read Syslog Policy: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "Syslog Policy read failed",
				Detail:   errMsg,
			},
		}
	}

	responseBody := &SyslogPolicy{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", responseBody.Meta.Name)
	d.Set("format", responseBody.Spec.Format)
	d.Set("filter", responseBody.Spec.Filter)
	d.Set("config", map[string]interface{}{
		"facility":         responseBody.Spec.Config.FacilityOverride,
		"disable_batching": responseBody.Spec.Config.DisableBatching,
	})
	d.Set("psm_target", map[string]bool{
		"enable": responseBody.Spec.PsmTarget.Enable,
	})

	targets := make([]map[string]string, len(responseBody.Spec.Targets))
	for i, target := range responseBody.Spec.Targets {
		targets[i] = map[string]string{
			"destination": target.Destination,
			"transport":   target.Transport,
		}
	}
	d.Set("targets", targets)

	log.Printf("[DEBUG] Syslog Policy read with UUID: %s", responseBody.Meta.UUID)

	return nil
}

func resourceSyslogPolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	syslogPolicy := &SyslogPolicy{}
	syslogPolicy.Meta.Name = d.Get("name").(string)
	syslogPolicy.Meta.Tenant = "default"
	syslogPolicy.Spec.Format = d.Get("format").(string)

	psmTarget := d.Get("psm_target").([]interface{})[0].(map[string]interface{})
	syslogPolicy.Spec.PsmTarget = PsmTarget{
		Enable: psmTarget["enable"].(bool),
	}

	filterInterface := d.Get("filter").([]interface{})
	filterStrings := make([]string, len(filterInterface))
	for i, v := range filterInterface {
		if v != nil {
			filterStrings[i] = v.(string)
		}
	}

	syslogConfig := d.Get("syslogconfig").([]interface{})[0].(map[string]interface{})
	syslogPolicy.Spec.Config = SyslogConfig{
		FacilityOverride: syslogConfig["facility"].(string),
		DisableBatching:  syslogConfig["disable_batching"].(bool),
	}

	syslogPolicy.Spec.Filter = filterStrings

	targets := d.Get("targets").([]interface{})
	for _, t := range targets {
		target := t.(map[string]interface{})
		syslogPolicy.Spec.Targets = append(syslogPolicy.Spec.Targets, Target{
			Destination: target["destination"].(string),
			Transport:   target["transport"].(string),
		})
	}

	jsonBytes, err := json.Marshal(syslogPolicy)
	if err != nil {
		log.Printf("[ERROR] Error marshalling Syslog Policy: %s", err)
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Updating Syslog Policy with name: %s", syslogPolicy.Meta.Name)

	fwlogPolicyName := d.Get("name").(string)
	req, err := http.NewRequestWithContext(ctx, "PUT", config.Server+"/configs/monitoring/v1/tenant/default/fwlogPolicy/"+fwlogPolicyName, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when updating Syslog Policy: %s", err)
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("failed to update Syslog Policy: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "Syslog Policy update failed",
				Detail:   errMsg,
			},
		}
	}

	responseBody := &SyslogPolicy{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responseBody.Meta.UUID)

	log.Printf("[DEBUG] Syslog Policy updated with UUID: %s", responseBody.Meta.UUID)

	return resourceSyslogPolicyRead(ctx, d, m)
}

func resourceSyslogPolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	fwlogPolicyName := d.Get("name").(string)
	req, err := http.NewRequestWithContext(ctx, "DELETE", config.Server+"/configs/monitoring/v1/tenant/default/fwlogPolicy/"+fwlogPolicyName, nil)
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when deleting Syslog Policy: %s", err)
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("failed to delete Syslog Policy: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "Syslog Policy deletion failed",
				Detail:   errMsg,
			},
		}
	}

	log.Printf("[DEBUG] Syslog Policy deleted with UUID: %s", d.Id())

	d.SetId("")

	return nil
}
