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
						},
						"type": {
							Type:     schema.TypeString,
							Required: true,
						},
						"source": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Required: true,
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
							MaxItems: 1,
							Required: true,
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
							MaxItems: 1,
							Required: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"protocol": {
										Type:     schema.TypeString,
										Required: true,
									},
									"ports": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},
						"translated_source": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Required: true,
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
							MaxItems: 1,
							Required: true,
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
							Required: true,
						},
					},
				},
			},
			"policy_distribution_targets": {
				Type:     schema.TypeList,
				Required: true,
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
		Rules []struct {
			Name    string `json:"name"`
			Disable bool   `json:"disable,omitempty"`
			Type    string `json:"type"`
			Source  struct {
				Addresses     []string `json:"addresses,omitempty"`
				IPCollections []string `json:"ipcollections,omitempty"`
			} `json:"source"`
			Destination struct {
				Addresses     []string `json:"addresses,omitempty"`
				IPCollections []string `json:"ipcollections,omitempty"`
			} `json:"destination"`
			DestinationProtoPort struct {
				Protocol string `json:"protocol"`
				Ports    string `json:"ports"`
			} `json:"destination-proto-port"`
			TranslatedSource struct {
				Addresses     []string `json:"addresses,omitempty"`
				IPCollections []string `json:"ipcollections,omitempty"`
			} `json:"translated-source"`
			TranslatedDestination struct {
				Addresses     []string `json:"addresses,omitempty"`
				IPCollections []string `json:"ipcollections,omitempty"`
			} `json:"translated-destination"`
			TranslatedDestinationPort string `json:"translated-destination-port"`
		} `json:"rules"`
		PolicyDistributionTargets []string `json:"policy-distribution-targets"`
	} `json:"spec"`
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
	natPolicy.Spec.Rules = make([]struct {
		Name    string `json:"name"`
		Disable bool   `json:"disable,omitempty"`
		Type    string `json:"type"`
		Source  struct {
			Addresses     []string `json:"addresses,omitempty"`
			IPCollections []string `json:"ipcollections,omitempty"`
		} `json:"source"`
		Destination struct {
			Addresses     []string `json:"addresses,omitempty"`
			IPCollections []string `json:"ipcollections,omitempty"`
		} `json:"destination"`
		DestinationProtoPort struct {
			Protocol string `json:"protocol"`
			Ports    string `json:"ports"`
		} `json:"destination-proto-port"`
		TranslatedSource struct {
			Addresses     []string `json:"addresses,omitempty"`
			IPCollections []string `json:"ipcollections,omitempty"`
		} `json:"translated-source"`
		TranslatedDestination struct {
			Addresses     []string `json:"addresses,omitempty"`
			IPCollections []string `json:"ipcollections,omitempty"`
		} `json:"translated-destination"`
		TranslatedDestinationPort string `json:"translated-destination-port"`
	}, len(rules))

	for i, rule := range rules {
		r := rule.(map[string]interface{})
		natPolicy.Spec.Rules[i].Name = r["name"].(string)
		natPolicy.Spec.Rules[i].Disable = r["disable"].(bool)
		natPolicy.Spec.Rules[i].Type = r["type"].(string)

		source := r["source"].([]interface{})[0].(map[string]interface{})
		natPolicy.Spec.Rules[i].Source.Addresses = expandStringList(source["addresses"].([]interface{}))
		natPolicy.Spec.Rules[i].Source.IPCollections = expandStringList(source["ipcollections"].([]interface{}))

		destination := r["destination"].([]interface{})[0].(map[string]interface{})
		natPolicy.Spec.Rules[i].Destination.Addresses = expandStringList(destination["addresses"].([]interface{}))
		natPolicy.Spec.Rules[i].Destination.IPCollections = expandStringList(destination["ipcollections"].([]interface{}))

		destProtoPort := r["destination_proto_port"].([]interface{})[0].(map[string]interface{})
		natPolicy.Spec.Rules[i].DestinationProtoPort.Protocol = destProtoPort["protocol"].(string)
		natPolicy.Spec.Rules[i].DestinationProtoPort.Ports = destProtoPort["ports"].(string)

		translatedSource := r["translated_source"].([]interface{})[0].(map[string]interface{})
		natPolicy.Spec.Rules[i].TranslatedSource.Addresses = expandStringList(translatedSource["addresses"].([]interface{}))
		natPolicy.Spec.Rules[i].TranslatedSource.IPCollections = expandStringList(translatedSource["ipcollections"].([]interface{}))

		translatedDest := r["translated_destination"].([]interface{})[0].(map[string]interface{})
		natPolicy.Spec.Rules[i].TranslatedDestination.Addresses = expandStringList(translatedDest["addresses"].([]interface{}))
		natPolicy.Spec.Rules[i].TranslatedDestination.IPCollections = expandStringList(translatedDest["ipcollections"].([]interface{}))

		natPolicy.Spec.Rules[i].TranslatedDestinationPort = r["translated_destination_port"].(string)
	}

	natPolicy.Spec.PolicyDistributionTargets = expandStringList(d.Get("policy_distribution_targets").([]interface{}))

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
		r["source"] = []interface{}{
			map[string]interface{}{
				"addresses":     rule.Source.Addresses,
				"ipcollections": rule.Source.IPCollections,
			},
		}
		r["destination"] = []interface{}{
			map[string]interface{}{
				"addresses":     rule.Destination.Addresses,
				"ipcollections": rule.Destination.IPCollections,
			},
		}
		r["destination_proto_port"] = []interface{}{
			map[string]interface{}{
				"protocol": rule.DestinationProtoPort.Protocol,
				"ports":    rule.DestinationProtoPort.Ports,
			},
		}
		r["translated_source"] = []interface{}{
			map[string]interface{}{
				"addresses":     rule.TranslatedSource.Addresses,
				"ipcollections": rule.TranslatedSource.IPCollections,
			},
		}
		r["translated_destination"] = []interface{}{
			map[string]interface{}{
				"addresses":     rule.TranslatedDestination.Addresses,
				"ipcollections": rule.TranslatedDestination.IPCollections,
			},
		}
		r["translated_destination_port"] = rule.TranslatedDestinationPort
		rules[i] = r
	}
	d.Set("rule", rules)

	d.Set("policy_distribution_targets", natPolicy.Spec.PolicyDistributionTargets)

	return nil
}

func resourceNATPolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	natPolicy := &NATPolicy{
		Kind:       "NATPolicy",
		APIVersion: "v1",
	}

	natPolicy.Meta.Tenant = "default"
	natPolicy.Meta.Namespace = "default"
	natPolicy.Meta.Name = d.Id()
	natPolicy.Meta.DisplayName = d.Get("display_name").(string)

	rules := d.Get("rule").([]interface{})
	natPolicy.Spec.Rules = make([]struct {
		Name    string `json:"name"`
		Disable bool   `json:"disable,omitempty"`
		Type    string `json:"type"`
		Source  struct {
			Addresses     []string `json:"addresses,omitempty"`
			IPCollections []string `json:"ipcollections,omitempty"`
		} `json:"source"`
		Destination struct {
			Addresses     []string `json:"addresses,omitempty"`
			IPCollections []string `json:"ipcollections,omitempty"`
		} `json:"destination"`
		DestinationProtoPort struct {
			Protocol string `json:"protocol"`
			Ports    string `json:"ports"`
		} `json:"destination-proto-port"`
		TranslatedSource struct {
			Addresses     []string `json:"addresses,omitempty"`
			IPCollections []string `json:"ipcollections,omitempty"`
		} `json:"translated-source"`
		TranslatedDestination struct {
			Addresses     []string `json:"addresses,omitempty"`
			IPCollections []string `json:"ipcollections,omitempty"`
		} `json:"translated-destination"`
		TranslatedDestinationPort string `json:"translated-destination-port"`
	}, len(rules))

	for i, rule := range rules {
		r := rule.(map[string]interface{})
		natPolicy.Spec.Rules[i].Name = r["name"].(string)
		natPolicy.Spec.Rules[i].Disable = r["disable"].(bool)
		natPolicy.Spec.Rules[i].Type = r["type"].(string)

		source := r["source"].([]interface{})[0].(map[string]interface{})
		natPolicy.Spec.Rules[i].Source.Addresses = expandStringList(source["addresses"].([]interface{}))
		natPolicy.Spec.Rules[i].Source.IPCollections = expandStringList(source["ipcollections"].([]interface{}))

		destination := r["destination"].([]interface{})[0].(map[string]interface{})
		natPolicy.Spec.Rules[i].Destination.Addresses = expandStringList(destination["addresses"].([]interface{}))
		natPolicy.Spec.Rules[i].Destination.IPCollections = expandStringList(destination["ipcollections"].([]interface{}))

		destProtoPort := r["destination_proto_port"].([]interface{})[0].(map[string]interface{})
		natPolicy.Spec.Rules[i].DestinationProtoPort.Protocol = destProtoPort["protocol"].(string)
		natPolicy.Spec.Rules[i].DestinationProtoPort.Ports = destProtoPort["ports"].(string)

		translatedSource := r["translated_source"].([]interface{})[0].(map[string]interface{})
		natPolicy.Spec.Rules[i].TranslatedSource.Addresses = expandStringList(translatedSource["addresses"].([]interface{}))
		natPolicy.Spec.Rules[i].TranslatedSource.IPCollections = expandStringList(translatedSource["ipcollections"].([]interface{}))

		translatedDest := r["translated_destination"].([]interface{})[0].(map[string]interface{})
		natPolicy.Spec.Rules[i].TranslatedDestination.Addresses = expandStringList(translatedDest["addresses"].([]interface{}))
		natPolicy.Spec.Rules[i].TranslatedDestination.IPCollections = expandStringList(translatedDest["ipcollections"].([]interface{}))

		natPolicy.Spec.Rules[i].TranslatedDestinationPort = r["translated_destination_port"].(string)
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
		r["source"] = []interface{}{
			map[string]interface{}{
				"addresses":     rule.Source.Addresses,
				"ipcollections": rule.Source.IPCollections,
			},
		}
		r["destination"] = []interface{}{
			map[string]interface{}{
				"addresses":     rule.Destination.Addresses,
				"ipcollections": rule.Destination.IPCollections,
			},
		}
		r["destination_proto_port"] = []interface{}{
			map[string]interface{}{
				"protocol": rule.DestinationProtoPort.Protocol,
				"ports":    rule.DestinationProtoPort.Ports,
			},
		}
		r["translated_source"] = []interface{}{
			map[string]interface{}{
				"addresses":     rule.TranslatedSource.Addresses,
				"ipcollections": rule.TranslatedSource.IPCollections,
			},
		}
		r["translated_destination"] = []interface{}{
			map[string]interface{}{
				"addresses":     rule.TranslatedDestination.Addresses,
				"ipcollections": rule.TranslatedDestination.IPCollections,
			},
		}
		r["translated_destination_port"] = rule.TranslatedDestinationPort
		rules[i] = r
	}
	d.Set("rule", rules)

	d.Set("policy_distribution_targets", natPolicy.Spec.PolicyDistributionTargets)

	return []*schema.ResourceData{d}, nil
}
