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

	// Assuming there is only one tunnel endpoint based on the schema
	teData := d.Get("tunnel_endpoints").([]interface{})[0].(map[string]interface{})

	// Create the IKESA and IPSECSA structs
	ikeSaData := teData["ike_sa"].([]interface{})[0].(map[string]interface{})
	ipsecSaData := teData["ipsec_sa"].([]interface{})[0].(map[string]interface{})
	localIdData := teData["local_identifier"].([]interface{})[0].(map[string]interface{})
	remoteIdData := teData["remote_identifier"].([]interface{})[0].(map[string]interface{})

	// Create the Tunnel struct with all the necessary nested structs
	tunnel := &Tunnel{
		Spec: TunnelSpec{
			HAMode:                    getString(teData, "ha_mode"),
			PolicyDistributionTargets: convertToStringSlice(d.Get("policy_distribution_targets").([]interface{})),
			TunnelEndpoints: []TunnelEndpoint{
				{
					InterfaceName: getString(teData, "interface_name"),
					DSE:           getString(teData, "dse"),
					IKEVersion:    getString(teData, "ike_version"),
					IKESA: &IKESA{
						IKEV1Mode:            getString(ikeSaData, "ikev1_mode"),
						EncryptionAlgorithms: convertToStringSlice(ikeSaData["encryption_algorithms"].([]interface{})),
						HashAlgorithms:       convertToStringSlice(ikeSaData["hash_algorithms"].([]interface{})),
						DHGroups:             convertToStringSlice(ikeSaData["dh_groups"].([]interface{})),
						RekeyLifetime:        getString(ikeSaData, "rekey_lifetime"),
						PreSharedKey:         getString(ikeSaData, "pre_shared_key"),
						ReauthLifetime:       getString(ikeSaData, "reauth_lifetime"),
						DPDDelay:             getString(ikeSaData, "dpd_delay"),
						IKEV1DPDTimeout:      getString(ikeSaData, "ikev1_dpd_timeout"),
						IKEInitiator:         getBool(ikeSaData, "ike_initiator"),
					},
					IPSECSA: &IPSECSA{
						EncryptionAlgorithms: convertToStringSlice(ipsecSaData["encryption_algorithms"].([]interface{})),
						DHGroups:             convertToStringSlice(ipsecSaData["dh_groups"].([]interface{})),
						RekeyLifetime:        getString(ipsecSaData, "rekey_lifetime"),
					},
					LocalIdentifier: Identifier{
						Type:  getString(localIdData, "type"),
						Value: getString(localIdData, "value"),
					},
					RemoteIdentifier: Identifier{
						Type:  getString(remoteIdData, "type"),
						Value: getString(remoteIdData, "value"),
					},
				},
			},
		},
	}

	// Convert the Tunnel struct into JSON for the API request
	jsonBytes, err := json.Marshal(tunnel)
	if err != nil {
		return diag.FromErr(err)
	}
	log.Printf("[DEBUG] Request JSON: %s\n", jsonBytes)

	// Make the HTTP POST request to create the tunnel
	req, err := http.NewRequestWithContext(ctx, "POST", config.Server+"/configs/security/v1/tenant/default/ipsecpolicies", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	// Add the session cookie and send the request
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})
	response, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer response.Body.Close()

	// Handle the response from the server
	if response.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(response.Body)
		errMsg := fmt.Sprintf("Failed to create Tunnel: HTTP %d %s: %s", response.StatusCode, response.Status, bodyBytes)
		return diag.Errorf("Tunnel creation failed: %s", errMsg)
	}

	// Read the response to get the tunnel ID and set it in the Terraform state
	responseTunnel := &Tunnel{}
	if err := json.NewDecoder(response.Body).Decode(responseTunnel); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(*responseTunnel.Meta.UUID)

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

// getBool retrieves a boolean from a map or returns false if the key is not found
func getBool(data map[string]interface{}, key string) bool {
	if val, ok := data[key]; ok {
		return val.(bool)
	}
	return false
}
