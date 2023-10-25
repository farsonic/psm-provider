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

func resourceRule() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceRuleCreate,
		ReadContext:   resourceRuleRead,
		DeleteContext: resourceRuleDelete,
		Schema: map[string]*schema.Schema{
			"name": {
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
	}
}

type RuleDetail struct {
	Apps              []string    `json:"apps"`
	Action            string      `json:"action"`
	FromIPCollections []string    `json:"from-ipcollections,omitempty"`
	ToIPCollections   []string    `json:"to-ipcollections,omitempty"`
	FromIPAddresses   []string    `json:"from-ip-addresses"`
	ToIPAddresses     []string    `json:"to-ip-addresses"`
	Description       string      `json:"description"`
	Name              string      `json:"name"`
	Disable           interface{} `json:"disable"`
}

type PolicyRule struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api-version"`
	Meta       struct {
		Name            string      `json:"name"`
		Tenant          string      `json:"tenant"`
		Namespace       string      `json:"namespace"`
		GenerationID    string      `json:"generation-id"`
		ResourceVersion string      `json:"resource-version"`
		UUID            string      `json:"uuid"`
		Labels          interface{} `json:"labels"`
		SelfLink        string      `json:"self-link"`
		DisplayName     interface{} `json:"display-name"`
	} `json:"meta"`
	Spec struct {
		AttachTenant              bool         `json:"attach-tenant "default:true`
		Rules                     []RuleDetail `json:"rules"`
		Priority                  interface{}  `json:"priority"`
		PolicyDistributionTargets []string     `json:"policy-distribution-targets"`
	} `json:"spec"`
	Status struct {
		PropagationStatus struct {
			GenerationID string `json:"generation-id"`
			Updated      int    `json:"updated"`
			Pending      int    `json:"pending"`
			MinVersion   string `json:"min-version"`
			Status       string `json:"status"`
			PdtStatus    []struct {
				Name    string `json:"name"`
				Updated int    `json:"updated"`
				Pending int    `json:"pending"`
				Status  string `json:"status"`
			} `json:"pdt-status"`
		} `json:"propagation-status"`
	} `json:"status"`
}

func validateAction(val interface{}, key string) (warns []string, errs []error) {
	v := val.(string)
	validActions := map[string]bool{
		"permit": true,
		"deny":   true,
		"reject": true,
	}

	if _, isValid := validActions[v]; !isValid {
		errs = append(errs, fmt.Errorf("%q must be either 'permit', 'deny', or 'reject', got: %s", key, v))
	}
	return
}

// Utility function to convert []interface{} to []string
func convertToStringSlice(data []interface{}) []string {
	result := make([]string, len(data))
	for i, v := range data {
		result[i] = v.(string)
	}
	return result
}
func resourceRuleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	// Get the rules JSON directly from the resource data
	rulesJSON := d.Get("rules_json").(string)

	// Debug logs to view the received JSON
	log.Printf("[DEBUG] Rules JSON received: %s", rulesJSON)

	// Deserialize the rules JSON into the appropriate Go struct
	var rules []PolicyRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		return diag.FromErr(err)
	}

	// Assuming you want to use the first rule in this function.
	// Note: If you want to loop through all the rules and apply logic for each one, you can expand on this logic.
	rule := rules[0]

	// Serialize the rule (or modified version of it) back to JSON
	jsonBytes, err := json.Marshal(rule)
	if err != nil {
		return diag.FromErr(err)
	}

	// Debug logs
	log.Printf("[DEBUG] Rule being sent to server: %s", string(jsonBytes))

	// Make the PUT request to update the policy
	policyName := d.Get("name").(string)
	if policyName == "" {
		return diag.Errorf("Missing policy name")
	}
	ruleURL := config.Server + "/configs/security/v1/tenant/default/networksecuritypolicies/" + policyName
	log.Printf("[DEBUG] URL being accessed: %s", ruleURL)
	req, err := http.NewRequestWithContext(ctx, "PUT", ruleURL, bytes.NewBuffer(jsonBytes))
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
		return diag.Errorf("failed to update rule: HTTP %d %s: %s", resp.StatusCode, resp.Status, string(bodyBytes))
	}

	responseBody := &PolicyRule{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responseBody.Meta.UUID)

	return nil
}

func resourceRuleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/security/v1/tenant/default/networksecuritypolicies/" + d.Get("name").(string)

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

	rule := &PolicyRule{}
	if err := json.NewDecoder(resp.Body).Decode(rule); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", rule.Meta.Name)
	d.Set("tenant", rule.Meta.Tenant)
	// Set other fields from the PolicyRule struct to the schema as required.

	return nil
}

func resourceRuleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/security/v1/tenant/default/networksecuritypolicies/" + d.Get("name").(string)

	log.Printf("[DEBUG] Deleting rule with URL: %s", url) // <-- Added debug log

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		log.Printf("[DEBUG] Error creating DELETE request: %s", err) // <-- Added debug log
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[DEBUG] Error executing DELETE request: %s", err) // <-- Added debug log
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		log.Printf("[DEBUG] Rule deletion failed with response: %s", string(bodyBytes)) // <-- Added debug log
		return diag.Errorf("failed to delete rule: HTTP %s", resp.Status)
	}

	d.SetId("")

	return nil
}
