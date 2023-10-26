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

// Define the Terraform resource schema for rules
func resourceRules() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceRulesCreate,
		ReadContext:   resourceRulesRead,
		DeleteContext: resourceRulesDelete,
		Schema: map[string]*schema.Schema{
			"policy_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"tenant": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "default",
				ForceNew: true,
			},
			"policy_distribution_target": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "default",
				ForceNew: true,
			},
			"rule": {
				Type:     schema.TypeList,
				Required: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"rule_name": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: true,
						},
						"description": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: true,
						},
						"from_ip_collections": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
							ForceNew: false,
						},
						"to_ip_collections": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
							ForceNew: false,
						},
						"from_ip_address": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
							ForceNew: false,
						},
						"to_ip_address": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
						},
						"apps": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
							ForceNew: true,
						},
						"action": {
							Type:         schema.TypeString,
							Optional:     true,
							ForceNew:     true,
							ValidateFunc: validateAction,
						},
					},
				},
			},
		},
	}
}

type NetworkSecurityPolicy struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api-version"`
	Meta       Meta   `json:"meta"`
	Spec       Spec   `json:"spec"`
	Status     Status `json:"status"`
}

type Meta struct {
	Name            string                 `json:"name"`
	Tenant          string                 `json:"tenant"`
	Namespace       string                 `json:"namespace"`
	GenerationID    string                 `json:"generation-id"`
	ResourceVersion string                 `json:"resource-version"`
	UUID            string                 `json:"uuid"`
	Labels          map[string]interface{} `json:"labels"`
	SelfLink        string                 `json:"self-link"`
	DisplayName     map[string]interface{} `json:"display-name"`
}

type Spec struct {
	AttachTenant              bool        `json:"attach-tenant"`
	Rules                     []Rule      `json:"rules"`
	Priority                  interface{} `json:"priority"`
	PolicyDistributionTargets []string    `json:"policy-distribution-targets"`
}

type Rule struct {
	Apps              []string    `json:"apps"`
	Action            string      `json:"action"`
	Description       string      `json:"description"`
	Name              string      `json:"name"`
	Disable           interface{} `json:"disable"`
	FromIPAddresses   []string    `json:"from-ip-addresses"`
	ToIPAddresses     []string    `json:"to-ip-addresses"`
	FromIPCollections []string    `json:"from-ipcollections"`
	ToIPCollections   []string    `json:"to-ipcollections"`
}

type Status struct {
	PropagationStatus PropagationStatus `json:"propagation-status"`
	RuleStatus        []RuleStatus      `json:"rule-status"`
}

type PropagationStatus struct {
	GenerationID string      `json:"generation-id"`
	Updated      int         `json:"updated"`
	Pending      int         `json:"pending"`
	MinVersion   string      `json:"min-version"`
	Status       string      `json:"status"`
	PdtStatus    []PdtStatus `json:"pdt-status"`
}

type PdtStatus struct {
	Name    string `json:"name"`
	Updated int    `json:"updated"`
	Pending int    `json:"pending"`
	Status  string `json:"status"`
}

type RuleStatus struct {
	RuleHash string `json:"rule-hash"`
}

func resourceRulesCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Create the initial empty policy here then start adding rules to it
	// This will be called when Update determines there is no Security Policy in place.
	// Uses a POST to create the Security Policy with a JSON Body and read the response.
	config := m.(*Config)
	client := config.Client()

	// Create and populate a GO Struct with the values read from the terraform schema resource.
	policy := &NetworkSecurityPolicy{
		Kind: "NetworkSecurityPolicy",
		Meta: Meta{
			Name:      d.Get("policy_name").(string),
			Tenant:    d.Get("tenant").(string),
			Namespace: d.Get("namespace").(string), // Added missing assignment for Namespace
		},
		Spec: Spec{
			PolicyDistributionTargets: []string{d.Get("policy_distribution_target").(string)},
		},
	}

	// Convert the GO Struct into JSON
	jsonBytes, err := json.Marshal(policy)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", config.Server+"/configs/security/v1/tenant/default/networksecuritypolicies", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	// Set SID cookie for authentication which we have learnt from the initial login process
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	response, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer response.Body.Close()

	// Check that we received a HTTP 200 from the PSM server, there will be errors here if the security policy already exists on the server.
	if response.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(response.Body)
		errMsg := fmt.Sprintf("Failed to create network: HTTP %d %s: %s", response.StatusCode, response.Status, bodyBytes)
		return diag.Errorf("Security Policy creation failed: %s", errMsg)
	}

	responsePolicy := &NetworkSecurityPolicy{}
	if err := json.NewDecoder(response.Body).Decode(responsePolicy); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responsePolicy.Meta.UUID)
	d.Set("policy_name", responsePolicy.Meta.Name)
	d.Set("tenant", responsePolicy.Meta.Tenant)
	d.Set("namespace", responsePolicy.Meta.Namespace)
	d.Set("generation_id", responsePolicy.Meta.GenerationID)
	d.Set("resource_version", responsePolicy.Meta.ResourceVersion)
	d.Set("self_link", responsePolicy.Meta.SelfLink)
	d.Set("attach_tenant", responsePolicy.Spec.AttachTenant)
	d.Set("policy_distribution_targets", responsePolicy.Spec.PolicyDistributionTargets)
	d.Set("propagation_status_generation_id", responsePolicy.Status.PropagationStatus.GenerationID)
	d.Set("updated", responsePolicy.Status.PropagationStatus.Updated)
	d.Set("pending", responsePolicy.Status.PropagationStatus.Pending)
	d.Set("min_version", responsePolicy.Status.PropagationStatus.MinVersion)
	d.Set("status", responsePolicy.Status.PropagationStatus.Status)
	return nil
}

func resourceRulesRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	url := config.Server + "/configs/network/v1/tenant/default/networks/" + d.Get("name").(string)
}

func resourceRulesUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	url := config.Server + "/configs/network/v1/tenant/default/networks/" + d.Get("name").(string)
}

func resourceRulesDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	url := config.Server + "/configs/network/v1/tenant/default/networks/" + d.Get("name").(string)
}

func getStringWithDefault(d *schema.ResourceData, key string, defaultValue string) string {
	if v, ok := d.GetOk(key); ok && v.(string) != "" {
		return v.(string)
	}
	return defaultValue
}
