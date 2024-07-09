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

func resourceOrchestrator() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceOrchestratorCreate,
		ReadContext:   resourceOrchestratorRead,
		UpdateContext: resourceOrchestratorUpdate,
		DeleteContext: resourceOrchestratorDelete,
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
			"auth_type": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: false,
			},
			"username": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: false,
			},
			"password": {
				Type:      schema.TypeString,
				Optional:  true,
				ForceNew:  false,
				Sensitive: true,
				//ValidateFunc: validation.StringLenBetween(8, 100),
			},
			"cert_data": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: false,
			},
			"cert_key": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: false,
			},
			"ca_data": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: false,
			},
			"disable_server_auth": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  "true",
				ForceNew: false,
			},
			"namespaces": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
							Default:  "all_namespaces",
						},
						"mode": {
							Type:     schema.TypeString,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
							Default:  "smartservicemonitored",
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
		UUID string `json:"uuid" default:"null"`
	} `json:"meta"`

	Spec struct {
		Type string `json:"type" default:"vcenter"`
		URI  string `json:"uri"`

		Credentials struct {
			AuthType          string `json:"auth-type" default:"username-password"`
			Username          string `json:"username" default:"null"`
			Password          string `json:"password" default:"null"`
			BearerToken       string `json:"bearer-token" default:"null"`
			CertData          string `json:"cert-data" default:"null"`
			KeyData           string `json:"key-data" default:"null"`
			CAData            string `json:"ca-data" default:"null"`
			DisableServerAuth bool   `json:"disable-server-authentication" default:"true"`
		} `json:"credentials"`

		Namespaces []Namespace `json:"namespaces"`
	}
}

func resourceOrchestratorCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	orchestrator := &Orchestrator{}
	orchestrator.Meta.Name = d.Get("name").(string)
	orchestrator.Spec.Type = d.Get("type").(string)
	orchestrator.Spec.URI = d.Get("uri").(string)
	orchestrator.Spec.Credentials.AuthType = d.Get("auth_type").(string)
	orchestrator.Spec.Credentials.Username = d.Get("username").(string)
	orchestrator.Spec.Credentials.Password = d.Get("password").(string)
	orchestrator.Spec.Credentials.CertData = d.Get("cert_data").(string)
	orchestrator.Spec.Credentials.KeyData = d.Get("cert_key").(string)
	orchestrator.Spec.Credentials.CAData = d.Get("ca_data").(string)
	orchestrator.Spec.Credentials.DisableServerAuth = d.Get("disable_server_auth").(bool)

	if v, ok := d.GetOk("namespace"); ok {
		for _, v := range v.([]interface{}) {
			NamespaceMap, ok := v.(map[string]interface{})
			if !ok {
				return diag.Errorf("unexpected type for namespaces: %T", v)
			}
			namespaces := Namespace{
				Name: NamespaceMap["name"].(string),
				Mode: NamespaceMap["mode"].(string),
			}
			orchestrator.Spec.Namespaces = append(orchestrator.Spec.Namespaces, namespaces)
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
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
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

	return append(diag.Diagnostics{}, resourceOrchestratorRead(ctx, d, m)...)
}

func resourceOrchestratorRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	// Construct the URL for the Orchestrator based on its UUID
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

	// Set the Terraform resource data
	d.Set("name", orchestrator.Meta.Name)
	d.Set("type", orchestrator.Spec.Type)
	d.Set("uri", orchestrator.Spec.URI)
	d.Set("auth_type", orchestrator.Spec.Credentials.AuthType)
	d.Set("username", orchestrator.Spec.Credentials.Username)
	d.Set("password", orchestrator.Spec.Credentials.Password)
	d.Set("cert_data", orchestrator.Spec.Credentials.CertData)
	d.Set("cert_key", orchestrator.Spec.Credentials.KeyData)
	d.Set("ca_data", orchestrator.Spec.Credentials.CAData)
	d.Set("disable_server_auth", orchestrator.Spec.Credentials.DisableServerAuth)

	return nil
}

func resourceOrchestratorUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	// Construct the URL for the network based on its name attached at the end
	url := config.Server + "/configs/orchestration/v1/orchestrator/" + d.Get("name").(string)

	// Get the current state of the resource
	orchestratorCurrent := &Orchestrator{}

	// Populate the orchestrator object with the new values
	orchestratorCurrent.Meta.Name = d.Get("name").(string)
	orchestratorCurrent.Spec.Type = d.Get("type").(string)
	orchestratorCurrent.Spec.URI = d.Get("uri").(string)
	orchestratorCurrent.Spec.Credentials.AuthType = d.Get("auth_type").(string)
	orchestratorCurrent.Spec.Credentials.Username = d.Get("username").(string)
	orchestratorCurrent.Spec.Credentials.Password = d.Get("password").(string)
	orchestratorCurrent.Spec.Credentials.CertData = d.Get("cert_data").(string)
	orchestratorCurrent.Spec.Credentials.KeyData = d.Get("cert_key").(string)
	orchestratorCurrent.Spec.Credentials.CAData = d.Get("ca_data").(string)
	orchestratorCurrent.Spec.Credentials.DisableServerAuth = d.Get("disable_server_auth").(bool)

	if v, ok := d.GetOk("namespace"); ok {
		for _, v := range v.([]interface{}) {
			NamespaceMap, ok := v.(map[string]interface{})
			if !ok {
				return diag.Errorf("unexpected type for namespaces: %T", v)
			}
			namespaces := Namespace{
				Name: NamespaceMap["name"].(string),
				Mode: NamespaceMap["mode"].(string),
			}
			orchestratorCurrent.Spec.Namespaces = append(orchestratorCurrent.Spec.Namespaces, namespaces)
		}
	}

	// Convert the orchestrator object to JSON
	jsonBytes, err := json.Marshal(orchestratorCurrent)
	if err != nil {
		return diag.FromErr(err)
	}
	log.Printf("[DEBUG] Request JSON: %s\n", jsonBytes)

	// Create a new HTTP request
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	// Set SID cookie for authentication
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	// Send the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	// Check the HTTP response
	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to update Orchestrator integration: HTTP %s", resp.Status)
	}

	responseBody := &Orchestrator{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return diag.FromErr(err)
	}
	log.Printf("[DEBUG] Response: %+v\n", responseBody)

	// No changes to the resource data, so just call the Read function to sync the state
	return resourceOrchestratorRead(ctx, d, m)
}

func resourceOrchestratorDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	// Construct the URL for the Orchestrator based on its name
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

	// Remove the resource from the Terraform state
	d.SetId("")

	return nil
}
