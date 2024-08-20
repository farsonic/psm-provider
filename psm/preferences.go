package psm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourcePSMUIGlobalSettings() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourcePSMUIGlobalSettingsCreateOrUpdate,
		ReadContext:   resourcePSMUIGlobalSettingsRead,
		UpdateContext: resourcePSMUIGlobalSettingsCreateOrUpdate,
		DeleteContext: resourcePSMUIGlobalSettingsDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourcePSMUIGlobalSettingsImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"duration": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "60m",
			},
			"warning_time": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "10s",
			},
			"enable_object_renaming": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
		},
	}
}

type UIGlobalSettings struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api-version"`
	Meta       struct {
		Name      string `json:"name"`
		Tenant    string `json:"tenant"`
		Namespace string `json:"namespace"`
	} `json:"meta"`
	Spec struct {
		StyleOptions string `json:"style-options"`
		IdleTimeout  struct {
			Duration    string `json:"duration"`
			WarningTime string `json:"warning-time"`
		} `json:"idle-timeout"`
		NetSecPoliciesBatchSize int  `json:"netsec-policies-batch-size"`
		EnableObjectRenaming    bool `json:"enable-object-renaming"`
	} `json:"spec"`
}

func resourcePSMUIGlobalSettingsCreateOrUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	uiGlobalSettings := &UIGlobalSettings{
		Kind:       "UIGlobalSettings",
		APIVersion: "v1",
	}
	uiGlobalSettings.Meta.Name = "default-ui-global-settings"
	uiGlobalSettings.Meta.Tenant = "default"
	uiGlobalSettings.Meta.Namespace = "default"
	uiGlobalSettings.Spec.IdleTimeout.Duration = d.Get("duration").(string)
	uiGlobalSettings.Spec.IdleTimeout.WarningTime = d.Get("warning_time").(string)
	uiGlobalSettings.Spec.EnableObjectRenaming = d.Get("enable_object_renaming").(bool)
	uiGlobalSettings.Spec.NetSecPoliciesBatchSize = 8

	jsonBytes, err := json.Marshal(uiGlobalSettings)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error marshalling UIGlobalSettings: %v", err))
	}

	url := fmt.Sprintf("%s/configs/preferences/v1/tenant/default/uiglobalsettings", config.Server)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating request: %v", err))
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error making request: %v", err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading response body: %v", err))
	}

	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error parsing response body: %v", err))
	}

	// Set the computed name in the ResourceData
	d.Set("name", "default-ui-global-settings")

	return resourcePSMUIGlobalSettingsRead(ctx, d, m)
}

func resourcePSMUIGlobalSettingsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := fmt.Sprintf("%s/configs/preferences/v1/tenant/default/uiglobalsettings", config.Server)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating request: %v", err))
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error making request: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("API request failed: %s", resp.Status)
	}

	var result UIGlobalSettings
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error decoding response: %v", err))
	}

	d.Set("name", "default-ui-global-settings")
	d.Set("duration", result.Spec.IdleTimeout.Duration)
	d.Set("warning_time", result.Spec.IdleTimeout.WarningTime)
	d.Set("enable_object_renaming", result.Spec.EnableObjectRenaming)

	return nil
}

func resourcePSMUIGlobalSettingsDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// UIGlobalSettings cannot be deleted, so we'll reset it to default values
	d.Set("duration", "60m")
	d.Set("warning_time", "10s")
	d.Set("enable_object_renaming", true)

	return resourcePSMUIGlobalSettingsCreateOrUpdate(ctx, d, m)
}

func resourcePSMUIGlobalSettingsImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	config := m.(*Config)
	if config.Server == "" {
		return nil, fmt.Errorf("provider server configuration is required for import")
	}

	// The ID for this resource is always "default-ui-global-settings"
	d.SetId("default-ui-global-settings")

	diags := resourcePSMUIGlobalSettingsRead(ctx, d, m)
	if diags.HasError() {
		return nil, fmt.Errorf("error reading UIGlobalSettings during import: %v", diags)
	}

	return []*schema.ResourceData{d}, nil
}
