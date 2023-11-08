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

func resourceTunnel() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceTunnelCreate,
		ReadContext:   resourceTunnelRead,
		UpdateContext: resourceTunnelUpdate,
		DeleteContext: resourceTunnelDelete,
		Schema: map[string]*schema.Schema{
			"kind": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"api_version": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"meta": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: true,
						},
						"tenant": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"namespace": {
							Type:     schema.TypeString,
							Computed: true,
							Optional: true,
						},
						"generation_id": {
							Type:     schema.TypeString,
							Computed: true,
							Optional: true,
						},
						"resource_version": {
							Type:     schema.TypeString,
							Computed: true,
							Optional: true,
						},
						"uuid": {
							Type:     schema.TypeString,
							Computed: true,
							Optional: true,
						},
						"labels": {
							Type:     schema.TypeString,
							Computed: true,
							Optional: true,
						},
						"self_link": {
							Type:     schema.TypeString,
							Computed: true,
							Optional: true,
						},
						"display_name": {
							Type:     schema.TypeString,
							Computed: true,
							Optional: true,
						},
					},
				},
			},
			"spec": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"ha_mode": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "no_ha",
						},
						"tunnel_endpoints": {
							Type:     schema.TypeList,
							Required: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"interface_name": {
										Type:     schema.TypeString,
										Required: true,
									},
									"dse": {
										Type:     schema.TypeString,
										Required: true,
									},
									"ike_version": {
										Type:     schema.TypeString,
										Required: true,
									},
									"ike_sa": {
										Type:     schema.TypeList,
										Optional: true,
										MaxItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"ikev1_mode": {
													Type:     schema.TypeString,
													Required: true,
												},
												"encryption_algorithms": {
													Type:     schema.TypeList,
													Required: true,
													Elem:     &schema.Schema{Type: schema.TypeString},
												},
												"hash_algorithms": {
													Type:     schema.TypeList,
													Required: true,
													Elem:     &schema.Schema{Type: schema.TypeString},
												},
												"dh_groups": {
													Type:     schema.TypeList,
													Required: true,
													Elem:     &schema.Schema{Type: schema.TypeString},
												},
												"rekey_lifetime": {
													Type:     schema.TypeString,
													Required: true,
												},
												"pre_shared_key": {
													Type:     schema.TypeString,
													Required: true,
												},
												"reauth_lifetime": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"dpd_delay": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"ikev1_dpd_timeout": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"ike_initiator": {
													Type:     schema.TypeBool,
													Optional: true,
												},
											},
										},
									},
									"ipsec_sa": {
										Type:     schema.TypeList,
										Optional: true,
										MaxItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"encryption_algorithms": {
													Type:     schema.TypeList,
													Required: true,
													Elem:     &schema.Schema{Type: schema.TypeString},
												},
												"dh_groups": {
													Type:     schema.TypeList,
													Required: true,
													Elem:     &schema.Schema{Type: schema.TypeString},
												},
												"rekey_lifetime": {
													Type:     schema.TypeString,
													Optional: true,
												},
											},
										},
									},
									"local_identifier": {
										Type:     schema.TypeList,
										Required: true,
										MaxItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"type": {
													Type:     schema.TypeString,
													Required: true,
												},
												"value": {
													Type:     schema.TypeString,
													Required: true,
												},
											},
										},
									},
									"remote_identifier": {
										Type:     schema.TypeList,
										Required: true,
										MaxItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"type": {
													Type:     schema.TypeString,
													Required: true,
												},
												"value": {
													Type:     schema.TypeString,
													Required: true,
												},
											},
										},
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
				},
			},
		},
	}
}

type Tunnel struct {
	Kind       *string    `json:"kind,omitempty"`
	APIVersion *string    `json:"api-version,omitempty"`
	Meta       TunnelMeta `json:"meta,omitempty"`
	Spec       TunnelSpec `json:"spec,omitempty"`
}

type TunnelMeta struct {
	Name            string                  `json:"name,omitempty"`
	Tenant          string                  `json:"tenant"`
	Namespace       *string                 `json:"namespace,omitempty"`
	GenerationID    *string                 `json:"generation-id,omitempty"`
	ResourceVersion *string                 `json:"resource-version,omitempty"`
	UUID            *string                 `json:"uuid,omitempty"`
	Labels          *map[string]interface{} `json:"labels,omitempty"`
	SelfLink        *string                 `json:"self-link,omitempty"`
	DisplayName     map[string]interface{}  `json:"display-name,omitempty"`
}

type TunnelSpec struct {
	HAMode                    string           `json:"ha-mode"`
	TunnelEndpoints           []TunnelEndpoint `json:"tunnel-endpoints"`
	PolicyDistributionTargets []string         `json:"policy-distribution-targets"`
}

type TunnelEndpoint struct {
	InterfaceName    string     `json:"interface-name"`
	DSE              string     `json:"dse"`
	IKEVersion       string     `json:"ike-version"`
	IKESA            *IKESA     `json:"ike-sa,omitempty"`
	IPSECSA          *IPSECSA   `json:"ipsec-sa,omitempty"`
	LocalIdentifier  Identifier `json:"local-identifier"`
	RemoteIdentifier Identifier `json:"remote-identifier"`
}

type IKESA struct {
	IKEV1Mode            string   `json:"ikev1-mode,omitempty"`
	EncryptionAlgorithms []string `json:"encryption-algorithms"`
	HashAlgorithms       []string `json:"hash-algorithms"`
	DHGroups             []string `json:"dh-groups"`
	RekeyLifetime        string   `json:"rekey-lifetime,omitempty"`
	PreSharedKey         string   `json:"pre-shared-key"`
	ReauthLifetime       string   `json:"reauth-lifetime,omitempty"`
	DPDDelay             string   `json:"dpd-delay,omitempty"`
	IKEV1DPDTimeout      string   `json:"ikev1-dpd-timeout,omitempty"`
	IKEInitiator         bool     `json:"ike-initiator,omitempty"`
}

type IPSECSA struct {
	EncryptionAlgorithms []string `json:"encryption-algorithms"`
	DHGroups             []string `json:"dh-groups"`
	RekeyLifetime        string   `json:"rekey-lifetime,omitempty"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func resourceTunnelCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	// Instantiate the Go Struct that we will populate with data from the resource to send to the PSM server eventually as JSON. If there is something
	// not being sent to the server correctly then ensure this structure is correct.
	tunnel := &Tunnel{
		Spec: TunnelSpec{
			PolicyDistributionTargets: convertToStringSlice(d.Get("policy_distribution_targets").([]interface{})),
			TunnelEndpoints:           make([]TunnelEndpoint, 0), // Initialize as an empty slice
		},
	}

	// Extract the tunnel_endpoints field which is a list of maps
	tunnelEndpointsData, ok := d.GetOk("tunnel_endpoints")
	if !ok {
		return diag.Errorf("tunnel_endpoints is required")
	}

	for _, te := range tunnelEndpointsData.([]interface{}) {
		teMap := te.(map[string]interface{})

		// Create a new TunnelEndpoint struct
		tunnelEndpoint := TunnelEndpoint{
			InterfaceName: teMap["interface_name"].(string),
			DSE:           teMap["dse"].(string),
			IKEVersion:    teMap["ike_version"].(string),
		}

		// IKESA
		if ikeSaList, ok := teMap["ike_sa"].([]interface{}); ok && len(ikeSaList) > 0 {
			ikeSaMap := ikeSaList[0].(map[string]interface{})
			ikeInitiator := false
			if ikeInitiatorPtr := getBool(ikeSaMap, "ike_initiator"); ikeInitiatorPtr != nil {
				ikeInitiator = *ikeInitiatorPtr
			}
			tunnelEndpoint.IKESA = &IKESA{
				IKEV1Mode:            getString(ikeSaMap, "ikev1_mode"),
				EncryptionAlgorithms: convertToStringSlice(ikeSaMap["encryption_algorithms"].([]interface{})),
				HashAlgorithms:       convertToStringSlice(ikeSaMap["hash_algorithms"].([]interface{})),
				DHGroups:             convertToStringSlice(ikeSaMap["dh_groups"].([]interface{})),
				RekeyLifetime:        getString(ikeSaMap, "rekey_lifetime"),
				PreSharedKey:         getString(ikeSaMap, "pre_shared_key"),
				ReauthLifetime:       getString(ikeSaMap, "reauth_lifetime"),
				DPDDelay:             getString(ikeSaMap, "dpd_delay"),
				IKEV1DPDTimeout:      getString(ikeSaMap, "ikev1_dpd_timeout"),
				IKEInitiator:         ikeInitiator,
			}
		}

		// IPSECSA
		if ipsecSaList, ok := teMap["ipsec_sa"].([]interface{}); ok && len(ipsecSaList) > 0 {
			ipsecSaMap := ipsecSaList[0].(map[string]interface{})
			tunnelEndpoint.IPSECSA = &IPSECSA{
				EncryptionAlgorithms: convertToStringSlice(ipsecSaMap["encryption_algorithms"].([]interface{})),
				DHGroups:             convertToStringSlice(ipsecSaMap["dh_groups"].([]interface{})),
				RekeyLifetime:        getString(ipsecSaMap, "rekey_lifetime"),
			}
		}

		// LocalIdentifier
		if localIdList, ok := teMap["local_identifier"].([]interface{}); ok && len(localIdList) > 0 {
			localIdMap := localIdList[0].(map[string]interface{})
			tunnelEndpoint.LocalIdentifier = Identifier{
				Type:  localIdMap["type"].(string),
				Value: localIdMap["value"].(string),
			}
		}

		// RemoteIdentifier
		if remoteIdList, ok := teMap["remote_identifier"].([]interface{}); ok && len(remoteIdList) > 0 {
			remoteIdMap := remoteIdList[0].(map[string]interface{})
			tunnelEndpoint.RemoteIdentifier = Identifier{
				Type:  remoteIdMap["type"].(string),
				Value: remoteIdMap["value"].(string),
			}
		}

		// Append the new TunnelEndpoint struct to the slice in TunnelSpec
		tunnel.Spec.TunnelEndpoints = append(tunnel.Spec.TunnelEndpoints, tunnelEndpoint)
	}

	// Convert the GO Struct into JSON
	jsonBytes, err := json.Marshal(tunnel)
	if err != nil {
		return diag.FromErr(err)
	}
	log.Printf("[DEBUG] Request JSON: %s\n", jsonBytes)

	req, err := http.NewRequestWithContext(ctx, "POST", config.Server+"/configs/security/v1/tenant/default/ipsecpolicies", bytes.NewBuffer(jsonBytes))
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
		errMsg := fmt.Sprintf("Failed to create Tunnel: HTTP %d %s: %s", response.StatusCode, response.Status, bodyBytes)
		return diag.Errorf("Tunnel creation failed: %s", errMsg)
	}

	//Read the response from the server and then use this to populate the local Terraform state
	responseTunnel := &Tunnel{}
	if err := json.NewDecoder(response.Body).Decode(responseTunnel); err != nil {
		return diag.FromErr(err)
	}

	responseJSON, _ := json.MarshalIndent(responseTunnel, "", "  ")
	log.Printf("[DEBUG] Response JSON: %s\n", responseJSON)

	d.SetId(*responseTunnel.Meta.UUID)
	d.Set("name", responseTunnel.Meta.Name)
	d.Set("tenant", responseTunnel.Meta.Tenant)

	/*
		rules := make([]interface{}, len(responseTunnel.Spec.Rules))
		for i, rule := range responseTunnel.Spec {
			rules[i] = map[string]interface{}{
				"name":                rule.Name,
				"action":              rule.Action,
				"description":         rule.Description,
				"apps":                rule.Apps,
				"from_ip_collections": rule.FromIPCollections,
				"to_ip_collections":   rule.ToIPCollections,
				"from_ip_addresses":   rule.FromIPAddresses,
				"to_ip_addresses":     rule.ToIPAddresses,
			}
		}

		if err := d.Set("spec", []interface{}{map[string]interface{}{
			"attach_tenant":               responseTunnel.Spec.AttachTenant,
			"rules":                       rules,
			"priority":                    responseTunnel.Spec.Priority,
			"policy_distribution_targets": responseTunnel.Spec.PolicyDistributionTargets,
		}}); err != nil {
			return diag.FromErr(err)
		}
		if err := d.Set("meta", []interface{}{map[string]interface{}{
			"name":             responseTunnel.Meta.Name,
			"tenant":           responseTunnel.Meta.Tenant,
			"namespace":        responseTunnel.Meta.Namespace,
			"generation_id":    responseTunnel.Meta.GenerationID,
			"resource_version": responseTunnel.Meta.ResourceVersion,
			"uuid":             responseTunnel.Meta.UUID,
			"labels":           responseTunnel.Meta.Labels,
			"self_link":        responseTunnel.Meta.SelfLink,
		}}); err != nil {
			return diag.FromErr(err)
		}
	*/

	return nil
}

func resourceTunnelRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Your read logic here
	// ...

	// Return diagnostics (which can include errors if any)
	return nil
}

func resourceTunnelUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Your update logic here
	// ...

	// Return diagnostics (which can include errors if any)
	return nil
}

func resourceTunnelDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Your delete logic here
	// ...

	// Return diagnostics (which can include errors if any)
	return nil
}

func getString(data map[string]interface{}, key string) string {
	if val, ok := data[key]; ok {
		return val.(string)
	}
	return ""
}

func getBool(data map[string]interface{}, key string) *bool {
	// Use GetOk to safely check for the presence of key
	if val, ok := data[key]; ok {
		// Check if the value is a bool and return a pointer to it
		if b, ok := val.(bool); ok {
			return &b
		}
	}
	// Return nil if the key is not found or the value is not a bool
	return nil
}
