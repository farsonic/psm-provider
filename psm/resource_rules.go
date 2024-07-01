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

func convertToStringSlice(input []interface{}) []string {
	result := make([]string, len(input))
	for i, v := range input {
		result[i] = v.(string)
	}
	return result
}

func validateAction(val interface{}, key string) (warns []string, errs []error) {
	v := val.(string)
	switch v {
	case "permit", "deny":
		// valid
	default:
		errs = append(errs, fmt.Errorf("%q must be either 'allow' or 'deny', got: %s", key, v))
	}
	return
}

// Define the Terraform resource schema for security policy. The schema defines how the local state is stored
// and can be populated at runtime based on the response from the PSM server.
func resourceRules() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceRulesCreate,
		ReadContext:   resourceRulesRead,
		UpdateContext: resourceRulesUpdate,
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
			"meta": {
				Type:     schema.TypeSet,
				Computed: true,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"tenant": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"namespace": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"generation_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"resource_version": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"uuid": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"labels": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"self_link": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
			"spec": {
				Type:     schema.TypeSet,
				Computed: true,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"attach_tenant": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"rules": {
							Type:     schema.TypeList,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									// Define the schema for a single rule here
									"name": {
										Type:     schema.TypeString,
										Optional: true,
										ForceNew: false,
									},
									"labels": {
										Type:     schema.TypeMap,
										Optional: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
									"action": {
										Type:     schema.TypeString,
										Required: true,
										ForceNew: false,
									},
									"description": {
										Type:     schema.TypeString,
										Optional: true,
										ForceNew: false,
									},
									"apps": {
										Type:     schema.TypeList,
										Elem:     &schema.Schema{Type: schema.TypeString},
										Optional: true,
										ForceNew: false,
									},
									"disable": {
										Type:     schema.TypeBool,
										Optional: true,
										ForceNew: false,
										Default:  false,
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
									"from_ip_addresses": {
										Type:     schema.TypeList,
										Elem:     &schema.Schema{Type: schema.TypeString},
										Optional: true,
										ForceNew: false,
									},
									"to_ip_addresses": {
										Type:     schema.TypeList,
										Elem:     &schema.Schema{Type: schema.TypeString},
										Optional: true,
										ForceNew: false,
									},
									"from_workloadgroups": {
										Type:     schema.TypeList,
										Elem:     &schema.Schema{Type: schema.TypeString},
										Optional: true,
										ForceNew: false,
									},
									"to_workloadgroups": {
										Type:     schema.TypeList,
										Elem:     &schema.Schema{Type: schema.TypeString},
										Optional: true,
										ForceNew: false,
									},
								},
							},
						},
						"priority": {
							Type:     schema.TypeInt,
							Optional: true,
							Default:  0,
							ForceNew: false,
						},
						"policy_distribution_targets": {
							Type:     schema.TypeList,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
							ForceNew: true,
						},
					},
				},
			},
			"rule": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: false,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"rule_name": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: false,
						},
						"description": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: false,
						},
						"labels": {
							Type:     schema.TypeMap,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"from_ip_collections": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
						},
						"to_ip_collections": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
						},
						"from_ip_addresses": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
						},
						"to_ip_addresses": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
						},
						"from_workloadgroups": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
						},
						"to_workloadgroups": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
						},
						"apps": {
							Type:     schema.TypeList,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
							ForceNew: false,
						},
						"action": {
							Type:         schema.TypeString,
							Required:     true,
							ForceNew:     false,
							ValidateFunc: validateAction,
						},
						"disable": {
							Type:     schema.TypeBool,
							Optional: true,
							ForceNew: false,
							Default:  false,
						},
					},
				},
			},
		},
	}
}

type NetworkSecurityPolicy struct {
	Kind       *string `json:"kind"`
	APIVersion *string `json:"api-version"`
	Meta       Meta    `json:"meta"`
	Spec       Spec    `json:"spec"`
	Status     Status  `json:"status"`
}

type Meta struct {
	Name            string                  `json:"name"`
	Tenant          string                  `json:"tenant"`
	Namespace       *string                 `json:"namespace"`
	GenerationID    *string                 `json:"generation-id"`
	ResourceVersion *string                 `json:"resource-version"`
	UUID            *string                 `json:"uuid"`
	Labels          *map[string]interface{} `json:"labels"`
	SelfLink        *string                 `json:"self-link"`
	DisplayName     map[string]interface{}  `json:"display-name"`
}

type Spec struct {
	AttachTenant              bool        `json:"attach-tenant"`
	Rules                     []Rule      `json:"rules"`
	Priority                  interface{} `json:"priority"`
	PolicyDistributionTargets []string    `json:"policy-distribution-targets"`
}

type Rule struct {
	Apps              []string          `json:"apps"`
	Action            string            `json:"action"`
	Description       string            `json:"description"`
	Name              string            `json:"name"`
	Labels            map[string]string `json:"labels,omitempty"`
	Disable           bool              `json:"disable"`
	FromIPAddresses   []string          `json:"from-ip-addresses"`
	ToIPAddresses     []string          `json:"to-ip-addresses"`
	FromIPCollections []string          `json:"from-ipcollections"`
	ToIPCollections   []string          `json:"to-ipcollections"`
	FromWorkloadGroup []string          `json:"from-workload-groups"`
	ToWorkloadGroup   []string          `json:"to-workload-groups"`
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

	// Create the GO Struct that we will populate with data from the resource to send to the PSM server eventually as JSON. If there is something
	// not being sent to the  server correctly the ensure this structure is correct.
	policy := &NetworkSecurityPolicy{
		Kind:       nil,
		APIVersion: nil,
		Meta: Meta{
			Name:            d.Get("policy_name").(string),
			Tenant:          d.Get("tenant").(string),
			Namespace:       nil,
			GenerationID:    nil,
			ResourceVersion: nil,
			UUID:            nil,
			Labels:          nil,
			SelfLink:        nil,
			DisplayName:     nil,
		},
		Spec: Spec{
			AttachTenant:              true,
			PolicyDistributionTargets: []string{d.Get("policy_distribution_target").(string)},
			Rules:                     []Rule{},
		},
	}

	if v, ok := d.GetOk("rule"); ok {
		for _, v := range v.([]interface{}) {
			ruleMap, ok := v.(map[string]interface{})
			if !ok {
				return diag.Errorf("unexpected type for rule: %T", v)
			}
			rule := Rule{
				Apps:              convertToStringSlice(ruleMap["apps"].([]interface{})),
				Action:            ruleMap["action"].(string),
				Description:       ruleMap["description"].(string),
				Name:              ruleMap["rule_name"].(string),
				Disable:           ruleMap["disable"].(bool),
				FromIPAddresses:   convertToStringSlice(ruleMap["from_ip_addresses"].([]interface{})),
				ToIPAddresses:     convertToStringSlice(ruleMap["to_ip_addresses"].([]interface{})),
				FromIPCollections: convertToStringSlice(ruleMap["from_ip_collections"].([]interface{})),
				ToIPCollections:   convertToStringSlice(ruleMap["to_ip_collections"].([]interface{})),
				FromWorkloadGroup: convertToStringSlice(ruleMap["from_workloadgroups"].([]interface{})),
				ToWorkloadGroup:   convertToStringSlice(ruleMap["to_workloadgroups"].([]interface{})),
			}

			if v, ok := ruleMap["labels"].(map[string]interface{}); ok {
				labels := make(map[string]string)
				for k, v := range v {
					labels[k] = v.(string)
				}
				rule.Labels = labels
			}

			policy.Spec.Rules = append(policy.Spec.Rules, rule)
		}
	}

	// Convert the GO Struct into JSON
	jsonBytes, err := json.Marshal(policy)
	if err != nil {
		return diag.FromErr(err)
	}
	log.Printf("[DEBUG] Request JSON: %s\n", jsonBytes)

	req, err := http.NewRequestWithContext(ctx, "POST", config.Server+"/configs/security/v1/tenant/default/networksecuritypolicies", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	// Grab the cookie and send the request to the server and deal with errors
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})
	response, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(response.Body)
		errMsg := fmt.Sprintf("Failed to create network: HTTP %d %s: %s", response.StatusCode, response.Status, bodyBytes)
		return diag.Errorf("Security Policy creation failed: %s", errMsg)
	}

	//Read the response from the server and then use this to populate the local Terraform state
	responsePolicy := &NetworkSecurityPolicy{}
	if err := json.NewDecoder(response.Body).Decode(responsePolicy); err != nil {
		return diag.FromErr(err)
	}

	responseJSON, _ := json.MarshalIndent(responsePolicy, "", "  ")
	log.Printf("[DEBUG] Response JSON: %s\n", responseJSON)

	//set the local Terraform state based on the response. This needs to line up with the schema we have defined above
	//but doesn't need to exactly match the PSM schema necessarily
	d.SetId(*responsePolicy.Meta.UUID)
	d.Set("policy_name", responsePolicy.Meta.Name)
	d.Set("tenant", responsePolicy.Meta.Tenant)

	rules := make([]interface{}, len(responsePolicy.Spec.Rules))
	for i, rule := range responsePolicy.Spec.Rules {
		rules[i] = map[string]interface{}{
			"name":                rule.Name,
			"action":              rule.Action,
			"description":         rule.Description,
			"apps":                rule.Apps,
			"disable":             rule.Disable,
			"from_ip_collections": rule.FromIPCollections,
			"to_ip_collections":   rule.ToIPCollections,
			"from_ip_addresses":   rule.FromIPAddresses,
			"to_ip_addresses":     rule.ToIPAddresses,
			"from_workloadgroups": rule.FromWorkloadGroup,
			"to_workloadgroups":   rule.ToWorkloadGroup,
		}
	}

	if err := d.Set("spec", []interface{}{map[string]interface{}{
		"attach_tenant":               responsePolicy.Spec.AttachTenant,
		"rules":                       rules,
		"priority":                    responsePolicy.Spec.Priority,
		"policy_distribution_targets": responsePolicy.Spec.PolicyDistributionTargets,
	}}); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("meta", []interface{}{map[string]interface{}{
		"name":             responsePolicy.Meta.Name,
		"tenant":           responsePolicy.Meta.Tenant,
		"namespace":        responsePolicy.Meta.Namespace,
		"generation_id":    responsePolicy.Meta.GenerationID,
		"resource_version": responsePolicy.Meta.ResourceVersion,
		"uuid":             responsePolicy.Meta.UUID,
		"labels":           responsePolicy.Meta.Labels,
		"self_link":        responsePolicy.Meta.SelfLink,
	}}); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func resourceRulesRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Read the current configuration
	config := m.(*Config)
	client := config.Client()
	policyName := d.Get("policy_name").(string)

	req, err := http.NewRequestWithContext(ctx, "GET", config.Server+"/configs/security/v1/tenant/default/networksecuritypolicies/"+policyName, nil)
	if err != nil {
		return diag.FromErr(err)
	}

	// Grab the cookie and send the request to the server and deal with errors
	// A GET request is going to return the state of the security policy but not the rules
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})
	response, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(response.Body)
		errMsg := fmt.Sprintf("Failed to create network: HTTP %d %s: %s", response.StatusCode, response.Status, bodyBytes)
		return diag.Errorf("Security Policy creation failed: %s", errMsg)
	}

	//Read the response from the server and then use this to populate the local Terraform state
	responsePolicy := &NetworkSecurityPolicy{}
	if err := json.NewDecoder(response.Body).Decode(responsePolicy); err != nil {
		return diag.FromErr(err)
	}

	responseJSON, _ := json.MarshalIndent(responsePolicy, "", "  ")
	log.Printf("[DEBUG] Response JSON: %s\n", responseJSON)

	//set the local Terraform state based on the response. This needs to line up with the schema we have defined above
	//but doesn't need to exactly match the PSM schema necessarily
	d.SetId(*responsePolicy.Meta.UUID)
	d.Set("policy_name", responsePolicy.Meta.Name)
	d.Set("tenant", responsePolicy.Meta.Tenant)

	rules := make([]interface{}, len(responsePolicy.Spec.Rules))
	for i, rule := range responsePolicy.Spec.Rules {
		rules[i] = map[string]interface{}{
			"name":                rule.Name,
			"action":              rule.Action,
			"description":         rule.Description,
			"apps":                rule.Apps,
			"disable":             rule.Disable,
			"from_ip_collections": rule.FromIPCollections,
			"to_ip_collections":   rule.ToIPCollections,
			"from_ip_addresses":   rule.FromIPAddresses,
			"to_ip_addresses":     rule.ToIPAddresses,
			"from_workloadgroups": rule.FromWorkloadGroup,
			"to_workloadgroups":   rule.ToWorkloadGroup,
		}
	}

	if err := d.Set("spec", []interface{}{map[string]interface{}{
		"attach_tenant":               responsePolicy.Spec.AttachTenant,
		"rules":                       rules,
		"priority":                    responsePolicy.Spec.Priority,
		"policy_distribution_targets": responsePolicy.Spec.PolicyDistributionTargets,
	}}); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("meta", []interface{}{map[string]interface{}{
		"name":             responsePolicy.Meta.Name,
		"tenant":           responsePolicy.Meta.Tenant,
		"namespace":        responsePolicy.Meta.Namespace,
		"generation_id":    responsePolicy.Meta.GenerationID,
		"resource_version": responsePolicy.Meta.ResourceVersion,
		"uuid":             responsePolicy.Meta.UUID,
		"labels":           responsePolicy.Meta.Labels,
		"self_link":        responsePolicy.Meta.SelfLink,
	}}); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func resourceRulesUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Create the initial empty policy here then start adding rules to it
	// This will be called when Update determines there is no Security Policy in place.
	// Uses a POST to create the Security Policy with a JSON Body and read the response.
	config := m.(*Config)
	client := config.Client()
	policyName := d.Get("policy_name").(string)

	// Create the GO Struct that we will populate with data from the resource to send to the PSM server eventually as JSON. If there is something
	// not being sent to the  server correctly the ensure this structure is correct.
	policy := &NetworkSecurityPolicy{
		Kind:       nil,
		APIVersion: nil,
		Meta: Meta{
			Name:            d.Get("policy_name").(string),
			Tenant:          d.Get("tenant").(string),
			Namespace:       nil,
			GenerationID:    nil,
			ResourceVersion: nil,
			UUID:            nil,
			Labels:          nil,
			SelfLink:        nil,
			DisplayName:     nil,
		},
		Spec: Spec{
			AttachTenant:              true,
			PolicyDistributionTargets: []string{d.Get("policy_distribution_target").(string)},
			Rules:                     []Rule{},
		},
	}

	if v, ok := d.GetOk("rule"); ok {
		for _, v := range v.([]interface{}) {
			ruleMap, ok := v.(map[string]interface{})
			if !ok {
				return diag.Errorf("unexpected type for rule: %T", v)
			}
			rule := Rule{
				Apps:              convertToStringSlice(ruleMap["apps"].([]interface{})),
				Action:            ruleMap["action"].(string),
				Description:       ruleMap["description"].(string),
				Name:              ruleMap["rule_name"].(string),
				Disable:           ruleMap["disable"].(bool),
				FromIPAddresses:   convertToStringSlice(ruleMap["from_ip_addresses"].([]interface{})),
				ToIPAddresses:     convertToStringSlice(ruleMap["to_ip_addresses"].([]interface{})),
				FromIPCollections: convertToStringSlice(ruleMap["from_ip_collections"].([]interface{})),
				ToIPCollections:   convertToStringSlice(ruleMap["to_ip_collections"].([]interface{})),
				FromWorkloadGroup: convertToStringSlice(ruleMap["from_workloadgroups"].([]interface{})),
				ToWorkloadGroup:   convertToStringSlice(ruleMap["to_workloadgroups"].([]interface{})),
			}

			if v, ok := ruleMap["labels"].(map[string]interface{}); ok {
				labels := make(map[string]string)
				for k, v := range v {
					labels[k] = v.(string)
				}
				rule.Labels = labels
			}

			policy.Spec.Rules = append(policy.Spec.Rules, rule)
		}
	}

	// Convert the GO Struct into JSON
	jsonBytes, err := json.Marshal(policy)
	if err != nil {
		return diag.FromErr(err)
	}
	log.Printf("[DEBUG] Request JSON: %s\n", jsonBytes)

	req, err := http.NewRequestWithContext(ctx, "PUT", config.Server+"/configs/security/v1/tenant/default/networksecuritypolicies/"+policyName, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	// Grab the cookie and send the request to the server and deal with errors
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})
	response, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(response.Body)
		errMsg := fmt.Sprintf("Failed to create network: HTTP %d %s: %s", response.StatusCode, response.Status, bodyBytes)
		return diag.Errorf("Security Policy creation failed: %s", errMsg)
	}

	//Read the response from the server and then use this to populate the local Terraform state
	responsePolicy := &NetworkSecurityPolicy{}
	if err := json.NewDecoder(response.Body).Decode(responsePolicy); err != nil {
		return diag.FromErr(err)
	}

	responseJSON, _ := json.MarshalIndent(responsePolicy, "", "  ")
	log.Printf("[DEBUG] Response JSON: %s\n", responseJSON)

	//set the local Terraform state based on the response. This needs to line up with the schema we have defined above
	//but doesn't need to exactly match the PSM schema necessarily
	d.SetId(*responsePolicy.Meta.UUID)
	d.Set("policy_name", responsePolicy.Meta.Name)
	d.Set("tenant", responsePolicy.Meta.Tenant)

	rules := make([]interface{}, len(responsePolicy.Spec.Rules))
	for i, rule := range responsePolicy.Spec.Rules {
		rules[i] = map[string]interface{}{
			"name":                rule.Name,
			"action":              rule.Action,
			"description":         rule.Description,
			"apps":                rule.Apps,
			"disable":             rule.Disable,
			"from_ip_collections": rule.FromIPCollections,
			"to_ip_collections":   rule.ToIPCollections,
			"from_ip_addresses":   rule.FromIPAddresses,
			"to_ip_addresses":     rule.ToIPAddresses,
			"from_workloadgroups": rule.FromWorkloadGroup,
			"to_workloadgroups":   rule.ToWorkloadGroup,
		}
	}

	if err := d.Set("spec", []interface{}{map[string]interface{}{
		"attach_tenant":               responsePolicy.Spec.AttachTenant,
		"rules":                       rules,
		"priority":                    responsePolicy.Spec.Priority,
		"policy_distribution_targets": responsePolicy.Spec.PolicyDistributionTargets,
	}}); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("meta", []interface{}{map[string]interface{}{
		"name":             responsePolicy.Meta.Name,
		"tenant":           responsePolicy.Meta.Tenant,
		"namespace":        responsePolicy.Meta.Namespace,
		"generation_id":    responsePolicy.Meta.GenerationID,
		"resource_version": responsePolicy.Meta.ResourceVersion,
		"uuid":             responsePolicy.Meta.UUID,
		"labels":           responsePolicy.Meta.Labels,
		"self_link":        responsePolicy.Meta.SelfLink,
	}}); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func resourceRulesDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Read the current configuration
	config := m.(*Config)
	client := config.Client()
	policyName := d.Get("policy_name").(string)

	req, err := http.NewRequestWithContext(ctx, "DELETE", config.Server+"/configs/security/v1/tenant/default/networksecuritypolicies/"+policyName, nil)
	if err != nil {
		return diag.FromErr(err)
	}

	// Grab the cookie and send the request to the server and deal with errors
	// A GET request is going to return the state of the security policy but not the rules
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})
	response, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(response.Body)
		errMsg := fmt.Sprintf("Failed to create network: HTTP %d %s: %s", response.StatusCode, response.Status, bodyBytes)
		return diag.Errorf("Security Policy creation failed: %s", errMsg)
	}

	//Read the response from the server and then use this to populate the local Terraform state
	responsePolicy := &NetworkSecurityPolicy{}
	if err := json.NewDecoder(response.Body).Decode(responsePolicy); err != nil {
		return diag.FromErr(err)
	}

	responseJSON, _ := json.MarshalIndent(responsePolicy, "", "  ")
	log.Printf("[DEBUG] Response JSON: %s\n", responseJSON)

	//set the local Terraform state based on the response. This needs to line up with the schema we have defined above
	//but doesn't need to exactly match the PSM schema necessarily

	return nil
}

func convertToBool(input interface{}) bool {
	return input.(bool)
}
