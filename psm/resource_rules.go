package psm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"

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
	config := m.(*Config)
	client := config.Client()

	log.Println("Initializing policy object...")

	policy := &NetworkSecurityPolicy{}
	policy.Kind = "NetworkSecurityPolicy"
	policy.Meta.Name = d.Get("policy_name").(string)
	policy.Meta.Tenant = d.Get("tenant").(string)
	policy.Meta.Namespace = d.Get("namespace").(string)
	policy.Spec.PolicyDistributionTargets = d.Get("policy_distribution_target").(string)

	log.Printf("Setting meta info: Name=%s, Tenant=%s, Namespace=%s\n", policy.Meta.Name, policy.Meta.Tenant, policy.Meta.Namespace)

	rules := d.Get("rule").([]interface{})

	for _, r := range rules {
		rule := r.(map[string]interface{})
		ruleName := rule["rule_name"].(string)
		if matched, _ := regexp.MatchString("^[a-zA-Z0-9].*[a-zA-Z0-9]$", ruleName); !matched {
			return diag.Errorf("invalid rule name: %s. The rule name must start and end with an alphanumeric character and can contain alphanumeric, -, _, and . characters in between", ruleName)
		}
		policy.Spec.AttachTenant = true
		policy.Spec.PolicyDistributionTargets = 
		policy.Spec.Rules = append(policy.Spec.Rules, Rule{
			Name:              rule["rule_name"].(string),
			Description:       rule["description"].(string),
			FromIPCollections: convertInterfaceSliceToStringSlice(rule["from_ip_collections"].([]interface{})),
			ToIPCollections:   convertInterfaceSliceToStringSlice(rule["to_ip_collections"].([]interface{})),
			Apps:              convertInterfaceSliceToStringSlice(rule["apps"].([]interface{})),
			Action:            rule["action"].(string),
		})
	}

	log.Println("Fetching the current policy...")
	existingPolicy, err := getCurrentPolicy(ctx, client, config, policy.Meta.Name)
	if err != nil {
		return diag.FromErr(err)
	}

	// Increment the GenerationID, add the UUID
	if existingPolicy != nil && existingPolicy.Meta.GenerationID != "" {
		currentID, err := strconv.Atoi(existingPolicy.Meta.GenerationID)
		if err != nil {
			return diag.FromErr(err)
		}
		newID := currentID + 1
		policy.Meta.GenerationID = strconv.Itoa(newID)

		currentUUID, err := strconv.Atoi(existingPolicy.Meta.UUID)
		if err != nil {
			return diag.FromErr(err)
		}
		policy.Meta.UUID = strconv.Itoa(currentUUID)
		policy.Meta.SelfLink = config.Server + "/configs/security/v1/tenant/default/networksecuritypolicies/" + policy.Meta.Name

	} else {
		// If policy doesn't exist or GenerationID is not set, set it to "1"
		policy.Meta.GenerationID = "1"
	}

	log.Printf("Setting GenerationID to: %s\n", policy.Meta.GenerationID)

	jsonBytes, err := json.Marshal(policy)
	if err != nil {
		return diag.FromErr(err)
	}

	log.Println("JSON to be sent to the server:")
	log.Println(string(jsonBytes))

	req, err := http.NewRequestWithContext(ctx, "PUT", config.Server+"/configs/security/v1/tenant/default/networksecuritypolicies/"+policy.Meta.Name, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	log.Println("Sending request to server...")
	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to create rule: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
	}

	log.Println("Decoding server response...")
	responsePolicy := &NetworkSecurityPolicy{}
	if err := json.NewDecoder(bytes.NewBuffer(bodyBytes)).Decode(responsePolicy); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("Setting resource ID to: %s\n", responsePolicy.Meta.Name)
	d.SetId(responsePolicy.Meta.Name)

	log.Println("Fetching rules from server...")
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

	policy := &NetworkSecurityPolicy{
		APIVersion: "v1",
	}
	if err := json.NewDecoder(resp.Body).Decode(policy); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

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

func getCurrentPolicy(ctx context.Context, client *http.Client, config *Config, policyName string) (*NetworkSecurityPolicy, error) {
	url := config.Server + "/configs/security/v1/tenant/default/networksecuritypolicies/" + policyName

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to read rule: HTTP %s", resp.Status)
	}

	policy := &NetworkSecurityPolicy{}
	if err := json.NewDecoder(resp.Body).Decode(policy); err != nil {
		return nil, err
	}

	return policy, nil
}
