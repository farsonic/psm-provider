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

func resourceOrchestrator() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceOrchestratorCreate,
		ReadContext:   resourceOrchestratorRead,
		UpdateContext: resourceOrchestratorUpdate,
		DeleteContext: resourceOrchestratorDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceOrchestratorImport,
		},
		Schema: map[string]*schema.Schema{
			"type": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"uri": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: false,
			},
			"username": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: false,
			},
			"password": {
				Type:      schema.TypeString,
				Required:  true,
				ForceNew:  false,
				Sensitive: true,
			},
			"ca_data": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: false,
			},
			"disable_server_authentication": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
				ForceNew: false,
			},
			"namespaces": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"mode": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
		},
	}
}

type Namespace struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
}

type Orchestrator struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api-version"`

	Meta struct {
		Name string `json:"name"`
		UUID string `json:"uuid,omitempty"`
	} `json:"meta"`

	Spec struct {
		Type string `json:"type"`
		URI  string `json:"uri"`

		Credentials struct {
			AuthType                    string `json:"auth-type"`
			Username                    string `json:"username"`
			Password                    string `json:"password,omitempty"`
			CAData                      string `json:"ca-data,omitempty"`
			DisableServerAuthentication bool   `json:"disable-server-authentication"`
		} `json:"credentials"`

		Namespaces []Namespace `json:"namespaces,omitempty"`
	} `json:"spec"`
}

func resourceOrchestratorCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	orchestrator := &Orchestrator{}
	orchestrator.Meta.Name = d.Get("name").(string)
	orchestrator.Spec.Type = d.Get("type").(string)
	orchestrator.Spec.URI = d.Get("uri").(string)
	orchestrator.Spec.Credentials.AuthType = "username-password"
	orchestrator.Spec.Credentials.Username = d.Get("username").(string)
	orchestrator.Spec.Credentials.Password = d.Get("password").(string)

	caData, hasCaData := d.GetOk("ca_data")
	if hasCaData {
		orchestrator.Spec.Credentials.CAData = caData.(string)
		orchestrator.Spec.Credentials.DisableServerAuthentication = false
	} else {
		disableServerAuth, hasDisableServerAuth := d.GetOk("disable_server_authentication")
		if hasDisableServerAuth {
			orchestrator.Spec.Credentials.DisableServerAuthentication = disableServerAuth.(bool)
		} else {
			orchestrator.Spec.Credentials.DisableServerAuthentication = true
		}
	}

	if v, ok := d.GetOk("namespaces"); ok {
		namespaces := v.([]interface{})
		orchestrator.Spec.Namespaces = make([]Namespace, len(namespaces))
		for i, ns := range namespaces {
			namespace := ns.(map[string]interface{})
			orchestrator.Spec.Namespaces[i] = Namespace{
				Name: namespace["name"].(string),
				Mode: namespace["mode"].(string),
			}
		}
	} else {
		// Always include the default namespace in the API request
		orchestrator.Spec.Namespaces = []Namespace{
			{
				Name: "all_namespaces",
				Mode: "smartservicemonitored",
			},
		}
	}

	jsonBytes, err := json.Marshal(orchestrator)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", config.Server+"/configs/orchestration/v1/orchestrator", bytes.NewBuffer(jsonBytes))
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
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return diag.FromErr(fmt.Errorf("failed to read error response body: %v", err))
		}
		errMsg := fmt.Sprintf("failed to create Orchestrator integration: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "Orchestrator Integration creation failed",
				Detail:   errMsg,
			},
		}
	}

	responseBody := &Orchestrator{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responseBody.Meta.UUID)

	return resourceOrchestratorRead(ctx, d, m)
}

func resourceOrchestratorRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/orchestration/v1/orchestrator/" + d.Get("name").(string)

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
		return diag.Errorf("Failed to read Orchestrator: HTTP %s", resp.Status)
	}

	orchestrator := &Orchestrator{}

	if err := json.NewDecoder(resp.Body).Decode(orchestrator); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", orchestrator.Meta.Name)
	d.Set("type", orchestrator.Spec.Type)
	d.Set("uri", orchestrator.Spec.URI)
	d.Set("username", orchestrator.Spec.Credentials.Username)

	if orchestrator.Spec.Credentials.CAData != "" {
		d.Set("ca_data", orchestrator.Spec.Credentials.CAData)
		d.Set("disable_server_authentication", false)
	} else {
		d.Set("disable_server_authentication", orchestrator.Spec.Credentials.DisableServerAuthentication)
	}

	// Handle namespaces
	if len(orchestrator.Spec.Namespaces) == 0 {
		d.Set("namespaces", []interface{}{
			map[string]interface{}{
				"name": "all_namespaces",
				"mode": "smartservicemonitored",
			},
		})
	} else {
		namespaces := make([]interface{}, len(orchestrator.Spec.Namespaces))
		for i, ns := range orchestrator.Spec.Namespaces {
			namespaces[i] = map[string]interface{}{
				"name": ns.Name,
				"mode": ns.Mode,
			}
		}
		d.Set("namespaces", namespaces)
	}

	return nil
}

func resourceOrchestratorUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/orchestration/v1/orchestrator/" + d.Get("name").(string)

	orchestratorCurrent := &Orchestrator{}
	orchestratorCurrent.Meta.Name = d.Get("name").(string)
	orchestratorCurrent.Spec.Type = d.Get("type").(string)
	orchestratorCurrent.Spec.URI = d.Get("uri").(string)
	orchestratorCurrent.Spec.Credentials.AuthType = "username-password"
	orchestratorCurrent.Spec.Credentials.Username = d.Get("username").(string)
	orchestratorCurrent.Spec.Credentials.Password = d.Get("password").(string)

	caData, hasCaData := d.GetOk("ca_data")
	if hasCaData {
		orchestratorCurrent.Spec.Credentials.CAData = caData.(string)
		orchestratorCurrent.Spec.Credentials.DisableServerAuthentication = false
	} else {
		disableServerAuth, hasDisableServerAuth := d.GetOk("disable_server_authentication")
		if hasDisableServerAuth {
			orchestratorCurrent.Spec.Credentials.DisableServerAuthentication = disableServerAuth.(bool)
		} else {
			orchestratorCurrent.Spec.Credentials.DisableServerAuthentication = true
		}
	}

	if v, ok := d.GetOk("namespaces"); ok {
		namespaces := v.([]interface{})
		orchestratorCurrent.Spec.Namespaces = make([]Namespace, len(namespaces))
		for i, ns := range namespaces {
			namespace := ns.(map[string]interface{})
			orchestratorCurrent.Spec.Namespaces[i] = Namespace{
				Name: namespace["name"].(string),
				Mode: namespace["mode"].(string),
			}
		}
	} else {
		// Set default namespace if not specified
		orchestratorCurrent.Spec.Namespaces = []Namespace{
			{
				Name: "all_namespaces",
				Mode: "smartservicemonitored",
			},
		}
	}

	jsonBytes, err := json.Marshal(orchestratorCurrent)
	if err != nil {
		return diag.FromErr(err)
	}
	log.Printf("[DEBUG] Update Request JSON: %s\n", jsonBytes)

	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonBytes))
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
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return diag.FromErr(fmt.Errorf("failed to read error response body: %v", err))
		}
		errMsg := fmt.Sprintf("failed to update Orchestrator integration: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "Orchestrator Integration update failed",
				Detail:   errMsg,
			},
		}
	}

	responseBody := &Orchestrator{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return diag.FromErr(err)
	}
	log.Printf("[DEBUG] Update Response: %+v\n", responseBody)

	return resourceOrchestratorRead(ctx, d, m)
}

func resourceOrchestratorDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/orchestration/v1/orchestrator/" + d.Get("name").(string)

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

	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("Failed to delete Orchestrator: HTTP %s", resp.Status)
	}

	d.SetId("")

	return nil
}

func resourceOrchestratorImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	config := m.(*Config)
	client := config.Client()

	// The ID is expected to be the name of the orchestrator
	name := d.Id()

	url := fmt.Sprintf("%s/configs/orchestration/v1/orchestrator/%s", config.Server, name)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %s", err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to import Orchestrator: HTTP %s", resp.Status)
	}

	orchestrator := &Orchestrator{}
	if err := json.NewDecoder(resp.Body).Decode(orchestrator); err != nil {
		return nil, fmt.Errorf("error decoding response: %s", err)
	}

	d.SetId(orchestrator.Meta.UUID)
	d.Set("name", orchestrator.Meta.Name)
	d.Set("type", orchestrator.Spec.Type)
	d.Set("uri", orchestrator.Spec.URI)
	d.Set("username", orchestrator.Spec.Credentials.Username)
	d.Set("disable_server_authentication", orchestrator.Spec.Credentials.DisableServerAuthentication)

	// Don't set the password, as it's not returned by the API
	// The user will need to set this manually after import

	if orchestrator.Spec.Credentials.CAData != "" {
		d.Set("ca_data", orchestrator.Spec.Credentials.CAData)
	}

	if len(orchestrator.Spec.Namespaces) > 0 {
		namespaces := make([]map[string]interface{}, len(orchestrator.Spec.Namespaces))
		for i, ns := range orchestrator.Spec.Namespaces {
			namespaces[i] = map[string]interface{}{
				"name": ns.Name,
				"mode": ns.Mode,
			}
		}
		d.Set("namespaces", namespaces)
	} else {
		// Set default namespace if none are specified
		d.Set("namespaces", []map[string]interface{}{
			{
				"name": "all_namespaces",
				"mode": "smartservicemonitored",
			},
		})
	}

	return []*schema.ResourceData{d}, nil
}
