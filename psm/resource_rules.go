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
			"namespace": {
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
							Required: true,
							ForceNew: true,
						},
						"description": {
							Type:     schema.TypeString,
							Required: true,
							ForceNew: true,
						},
						"from_ip_collections": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
							ForceNew: true,
						},
						"to_ip_collections": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
							ForceNew: true,
						},
						"from_ip_address": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
							ForceNew: true,
						},
						"to_ip_address": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
							ForceNew: true,
						},
						"apps": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
							ForceNew: true,
						},
						"action": {
							Type:         schema.TypeString,
							Required:     true,
							ForceNew:     true,
							ValidateFunc: validateAction,
						},
					},
				},
			},
		},
	}
}

func validateActions(val interface{}, key string) ([]string, []error) {
	// Placeholder for any validation you want to implement on the action field.
	return nil, nil
}

type NetworkSecurityPolicy struct {
	Kind   string `json:"kind"`
	Spec   Spec   `json:"spec"`
	Meta   Meta   `json:"meta"`
	Status Status `json:"status"`
}

type Meta struct {
	Name      string `json:"name"`
	Tenant    string `json:"tenant"`
	Namespace string `json:"namespace"`
}

type Spec struct {
	Rules []Rule `json:"rules"`
}

type Rule struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	FromIPCollections []string `json:"from-ipcollections"`
	ToIPCollections   []string `json:"to-ipcollections"`
	Apps              []string `json:"apps"`
	Action            string   `json:"action"`
}

type Status struct {
	// Placeholder for any status fields you need.
}

func resourceRulesCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	policy := &NetworkSecurityPolicy{}
	policy.Kind = "NetworkSecurityPolicy"
	policy.Meta.Name = d.Get("policy_name").(string)
	policy.Meta.Tenant = d.Get("tenant").(string)
	policy.Meta.Namespace = d.Get("namespace").(string)

	rules := d.Get("rule").([]interface{})

	for _, r := range rules {
		rule := r.(map[string]interface{})
		policy.Spec.Rules = append(policy.Spec.Rules, Rule{
			Name:              rule["rule_name"].(string),
			Description:       rule["description"].(string),
			FromIPCollections: convertInterfaceSliceToStringSlice(rule["from_ip_collections"].([]interface{})),
			ToIPCollections:   convertInterfaceSliceToStringSlice(rule["to_ip_collections"].([]interface{})),
			Apps:              convertInterfaceSliceToStringSlice(rule["apps"].([]interface{})),
			Action:            rule["action"].(string),
		})
	}

	jsonBytes, err := json.Marshal(policy)

	if err != nil {
		return diag.FromErr(err)
	}
	fmt.Println(string(jsonBytes))

	req, err := http.NewRequestWithContext(ctx, "PUT", config.Server+"/configs/security/v1/tenant/default/networksecuritypolicies", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to create rule: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
	}

	responsePolicy := &NetworkSecurityPolicy{}
	if err := json.NewDecoder(bytes.NewBuffer(bodyBytes)).Decode(responsePolicy); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responsePolicy.Meta.Name)

	return resourceRuleRead(ctx, d, m)
}

func resourceRulesRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/security/v1/tenant/default/networksecuritypolicies/" + d.Get("policy_name").(string)

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
		return diag.Errorf("failed to read rule: HTTP %s", resp.Status)
	}

	policy := &NetworkSecurityPolicy{}
	if err := json.NewDecoder(resp.Body).Decode(policy); err != nil {
		return diag.FromErr(err)
	}

	// Update the Terraform state based on the response from the server
	// Placeholder code, you might need to adjust for your specific schema and data

	return nil
}

// Implement the Delete method for rules
func resourceRulesDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/security/v1/tenant/default/networksecuritypolicies/" + d.Get("policy_name").(string)

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
		return diag.Errorf("failed to delete rule: HTTP %s", resp.Status)
	}

	return nil
}

func convertInterfaceSliceToStringSlice(input []interface{}) []string {
	var output []string
	for _, v := range input {
		output = append(output, v.(string))
	}
	return output
}
