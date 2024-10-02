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

func resourceNATPolicy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceNATPolicyCreate,
		ReadContext:   resourceNATPolicyRead,
		UpdateContext: resourceNATPolicyUpdate,
		DeleteContext: resourceNATPolicyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceNATPolicyImport,
		},
		Schema: map[string]*schema.Schema{
			"display_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"rule": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"disable": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
						"type": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "static",
						},
						"source": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"addresses": {
										Type:     schema.TypeList,
										Optional: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
									"ipcollections": {
										Type:     schema.TypeList,
										Optional: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
								},
							},
						},
						"destination": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"addresses": {
										Type:     schema.TypeList,
										Optional: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
									"ipcollections": {
										Type:     schema.TypeList,
										Optional: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
								},
							},
						},
						"destination_proto_port": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"protocol": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"ports": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
						"translated_source": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"addresses": {
										Type:     schema.TypeList,
										Optional: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
									"ipcollections": {
										Type:     schema.TypeList,
										Optional: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
								},
							},
						},
						"translated_destination": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"addresses": {
										Type:     schema.TypeList,
										Optional: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
									"ipcollections": {
										Type:     schema.TypeList,
										Optional: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
								},
							},
						},
						"translated_destination_port": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"policy_distribution_targets": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

type NATPolicy struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api-version"`
	Meta       struct {
		Name        string `json:"name"`
		Tenant      string `json:"tenant"`
		Namespace   string `json:"namespace"`
		UUID        string `json:"uuid"`
		DisplayName string `json:"display-name"`
	} `json:"meta"`
	Spec struct {
		Rules                     []NatRule `json:"rules"`
		PolicyDistributionTargets []string  `json:"policy-distribution-targets,omitempty"`
	} `json:"spec"`
}

type NatRule struct {
	Name                 string             `json:"name"`
	Disable              bool               `json:"disable,omitempty"`
	Type                 string             `json:"type"`
	Source               *AddressCollection `json:"source,omitempty"`
	Destination          *AddressCollection `json:"destination,omitempty"`
	DestinationProtoPort struct {
		Protocol string `json:"protocol,omitempty"`
		Ports    string `json:"ports,omitempty"`
	} `json:"destination-proto-port,omitempty"`
	TranslatedSource          *AddressCollection `json:"translated-source,omitempty"`
	TranslatedDestination     *AddressCollection `json:"translated-destination,omitempty"`
	TranslatedDestinationPort string             `json:"translated-destination-port,omitempty"`
}
type AddressCollection struct {
	Addresses     []string `json:"addresses,omitempty"`
	IPCollections []string `json:"ipcollections,omitempty"`
	Any           bool     `json:"any,omitempty"`
}

func resourceNATPolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	natPolicy := &NATPolicy{
		Kind:       "NATPolicy",
		APIVersion: "v1",
	}
	natPolicy.Meta.Tenant = "default"
	natPolicy.Meta.Namespace = "default"
	natPolicy.Meta.DisplayName = d.Get("display_name").(string)

	rules := d.Get("rule").([]interface{})
	if err := validateNATRules(rules); err != nil {
		return diag.FromErr(err)
	}

	natPolicy.Spec.Rules = make([]NatRule, 0, len(rules))
	for _, rule := range rules {
		natRule := createNatRule(rule.(map[string]interface{}))
		natPolicy.Spec.Rules = append(natPolicy.Spec.Rules, natRule)
	}

	if v, ok := d.GetOk("policy_distribution_targets"); ok {
		natPolicy.Spec.PolicyDistributionTargets = expandStringList(v.([]interface{}))
	}

	jsonData, err := json.Marshal(natPolicy)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/configs/network/v1/tenant/default/natpolicies", config.Server), bytes.NewBuffer(jsonData))
	if err != nil {
		return diag.FromErr(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	res, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return diag.Errorf("failed to read error response body: %v", err)
		}
		return diag.Errorf("failed to create NAT policy: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var createdPolicy NATPolicy
	if err := json.NewDecoder(res.Body).Decode(&createdPolicy); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdPolicy.Meta.UUID)

	return resourceNATPolicyRead(ctx, d, m)
}

func resourceNATPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/network/v1/tenant/default/natpolicies/%s", config.Server, d.Id()), nil)
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	res, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotFound {
		d.SetId("")
		return nil
	}

	if res.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return diag.Errorf("failed to read error response body: %v", err)
		}
		return diag.Errorf("failed to read NAT policy: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var natPolicy NATPolicy
	if err := json.NewDecoder(res.Body).Decode(&natPolicy); err != nil {
		return diag.FromErr(err)
	}

	d.Set("display_name", natPolicy.Meta.DisplayName)

	rules := make([]interface{}, len(natPolicy.Spec.Rules))
	for i, rule := range natPolicy.Spec.Rules {
		r := make(map[string]interface{})
		r["name"] = rule.Name
		r["disable"] = rule.Disable
		r["type"] = rule.Type

		if rule.Source != nil {
			r["source"] = []interface{}{
				map[string]interface{}{
					"addresses":     rule.Source.Addresses,
					"ipcollections": rule.Source.IPCollections,
				},
			}
		}

		if rule.Destination != nil {
			r["destination"] = []interface{}{
				map[string]interface{}{
					"addresses":     rule.Destination.Addresses,
					"ipcollections": rule.Destination.IPCollections,
				},
			}
		}

		if rule.DestinationProtoPort.Protocol != "" || rule.DestinationProtoPort.Ports != "" {
			r["destination_proto_port"] = []interface{}{
				map[string]interface{}{
					"protocol": rule.DestinationProtoPort.Protocol,
					"ports":    rule.DestinationProtoPort.Ports,
				},
			}
		}

		if rule.TranslatedSource != nil {
			r["translated_source"] = []interface{}{
				map[string]interface{}{
					"addresses":     rule.TranslatedSource.Addresses,
					"ipcollections": rule.TranslatedSource.IPCollections,
				},
			}
		}

		if rule.TranslatedDestination != nil {
			r["translated_destination"] = []interface{}{
				map[string]interface{}{
					"addresses":     rule.TranslatedDestination.Addresses,
					"ipcollections": rule.TranslatedDestination.IPCollections,
				},
			}
		}

		if rule.TranslatedDestinationPort != "" {
			r["translated_destination_port"] = rule.TranslatedDestinationPort
		}

		rules[i] = r
	}

	if err := d.Set("rule", rules); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("policy_distribution_targets", natPolicy.Spec.PolicyDistributionTargets); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceNATPolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	natPolicy := &NATPolicy{
		Kind:       "NATPolicy",
		APIVersion: "v1",
	}

	natPolicy.Meta.Name = d.Id()
	natPolicy.Meta.DisplayName = d.Get("display_name").(string)
	natPolicy.Meta.Tenant = "default"
	natPolicy.Meta.Namespace = "default"

	rules := d.Get("rule").([]interface{})
	if err := validateNATRules(rules); err != nil {
		return diag.FromErr(err)
	}

	natPolicy.Spec.Rules = make([]NatRule, 0, len(rules))
	for _, rule := range rules {
		natRule := createNatRule(rule.(map[string]interface{}))
		natPolicy.Spec.Rules = append(natPolicy.Spec.Rules, natRule)
	}

	natPolicy.Spec.PolicyDistributionTargets = expandStringList(d.Get("policy_distribution_targets").([]interface{}))

	jsonData, err := json.Marshal(natPolicy)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s/configs/network/v1/tenant/default/natpolicies/%s", config.Server, d.Id()), bytes.NewBuffer(jsonData))
	if err != nil {
		return diag.FromErr(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	res, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer res.Body.Close()

	if v, ok := d.GetOk("policy_distribution_targets"); ok {
		natPolicy.Spec.PolicyDistributionTargets = expandStringList(v.([]interface{}))
	} else {
		natPolicy.Spec.PolicyDistributionTargets = nil
	}

	if res.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return diag.Errorf("failed to read error response body: %v", err)
		}
		return diag.Errorf("failed to update NAT policy: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	return resourceNATPolicyRead(ctx, d, m)
}

func resourceNATPolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	req, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s/configs/network/v1/tenant/default/natpolicies/%s", config.Server, d.Id()), nil)
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	res, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return diag.Errorf("failed to read error response body: %v", err)
		}
		return diag.Errorf("failed to delete NAT policy: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	d.SetId("")

	return nil
}

func resourceNATPolicyImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	config := m.(*Config)
	client := config.Client()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/network/v1/tenant/default/natpolicies/%s", config.Server, d.Id()), nil)
	if err != nil {
		return nil, err
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read error response body: %v", err)
		}
		return nil, fmt.Errorf("failed to import NAT policy: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var natPolicy NATPolicy
	if err := json.NewDecoder(res.Body).Decode(&natPolicy); err != nil {
		return nil, err
	}

	d.Set("display_name", natPolicy.Meta.DisplayName)

	rules := make([]interface{}, len(natPolicy.Spec.Rules))
	for i, rule := range natPolicy.Spec.Rules {
		r := make(map[string]interface{})
		r["name"] = rule.Name
		r["disable"] = rule.Disable
		r["type"] = rule.Type

		if rule.Source != nil && (len(rule.Source.Addresses) > 0 || len(rule.Source.IPCollections) > 0) {
			r["source"] = []interface{}{
				map[string]interface{}{
					"addresses":     rule.Source.Addresses,
					"ipcollections": rule.Source.IPCollections,
				},
			}
		}
		if !rule.Destination.Any {
			r["destination"] = []interface{}{
				map[string]interface{}{
					"addresses":     rule.Destination.Addresses,
					"ipcollections": rule.Destination.IPCollections,
				},
			}
		}
		if rule.DestinationProtoPort.Protocol != "" {
			r["destination_proto_port"] = []interface{}{
				map[string]interface{}{
					"protocol": rule.DestinationProtoPort.Protocol,
					"ports":    rule.DestinationProtoPort.Ports,
				},
			}
		}
		if len(rule.TranslatedSource.Addresses) > 0 || len(rule.TranslatedSource.IPCollections) > 0 {
			r["translated_source"] = []interface{}{
				map[string]interface{}{
					"addresses":     rule.TranslatedSource.Addresses,
					"ipcollections": rule.TranslatedSource.IPCollections,
				},
			}
		}
		if len(rule.TranslatedDestination.Addresses) > 0 || len(rule.TranslatedDestination.IPCollections) > 0 {
			r["translated_destination"] = []interface{}{
				map[string]interface{}{
					"addresses":     rule.TranslatedDestination.Addresses,
					"ipcollections": rule.TranslatedDestination.IPCollections,
				},
			}
		}
		if rule.TranslatedDestinationPort != "" {
			r["translated_destination_port"] = rule.TranslatedDestinationPort
		}
		rules[i] = r
	}
	d.Set("rule", rules)

	d.Set("policy_distribution_targets", natPolicy.Spec.PolicyDistributionTargets)

	return []*schema.ResourceData{d}, nil
}
