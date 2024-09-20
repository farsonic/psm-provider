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

func resourceIPSecPolicy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceIPSecPolicyCreate,
		ReadContext:   resourceIPSecPolicyRead,
		UpdateContext: resourceIPSecPolicyUpdate,
		DeleteContext: resourceIPSecPolicyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceIPSecPolicyImport,
		},
		Schema: map[string]*schema.Schema{
			"kind": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"api_version": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"display_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"tunnel": {
				Type:     schema.TypeList,
				MaxItems: 1,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"ha_mode": {
							Type:     schema.TypeString,
							Required: true,
						},
						"policy_distribution_targets": {
							Type:     schema.TypeList,
							Required: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"disable_tcp_mss_adjust": {
							Type:     schema.TypeBool,
							Optional: true,
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
										MaxItems: 1,
										Required: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
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
													Type:      schema.TypeString,
													Optional:  true,
													Sensitive: true,
												},
												"reauth_lifetime": {
													Type:     schema.TypeString,
													Required: true,
												},
												"dpd_delay": {
													Type:     schema.TypeString,
													Required: true,
												},
												"ikev1_dpd_timeout": {
													Type:     schema.TypeString,
													Required: true,
												},
												"ike_initiator": {
													Type:     schema.TypeBool,
													Required: true,
												},
												"auth_type": {
													Type:     schema.TypeString,
													Required: true,
												},
												"local_identity_certificates": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"remote_ca_certificates": {
													Type:     schema.TypeList,
													Optional: true,
													Elem:     &schema.Schema{Type: schema.TypeString},
												},
											},
										},
									},
									"ipsec_sa": {
										Type:     schema.TypeList,
										MaxItems: 1,
										Required: true,
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
													Required: true,
												},
											},
										},
									},
									"local_identifier": {
										Type:     schema.TypeList,
										MaxItems: 1,
										Required: true,
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
										MaxItems: 1,
										Required: true,
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
									"lifetime": {
										Type:     schema.TypeList,
										MaxItems: 1,
										Optional: true,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"sa_lifetime": {
													Type:             schema.TypeString,
													Optional:         true,
													Computed:         true,
													DiffSuppressFunc: suppressMissingLifetimeValues,
												},
												"ike_lifetime": {
													Type:             schema.TypeString,
													Optional:         true,
													Computed:         true,
													DiffSuppressFunc: suppressMissingLifetimeValues,
												},
											},
										},
									},
								},
							},
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
	Tenant          string                  `json:"tenant,omitempty"`
	Namespace       string                  `json:"namespace,omitempty"`
	DisplayName     string                  `json:"display-name,omitempty"`
	GenerationID    *string                 `json:"generation-id,omitempty"`
	ResourceVersion *string                 `json:"resource-version,omitempty"`
	UUID            *string                 `json:"uuid,omitempty"`
	Labels          *map[string]interface{} `json:"labels,omitempty"`
	SelfLink        *string                 `json:"self-link,omitempty"`
}

type TunnelSpec struct {
	HAMode                    string           `json:"ha-mode,omitempty"`
	TunnelEndpoints           []TunnelEndpoint `json:"tunnel-endpoints,omitempty"`
	PolicyDistributionTargets []string         `json:"policy-distribution-targets,omitempty"`
	DisableTCPMSSAdjust       bool             `json:"disable-tcp-mss-adjust,omitempty"`
	Config                    *TunnelConfig    `json:"config,omitempty"`
}

type TunnelConfig struct {
	SALifetime  string `json:"sa-lifetime,omitempty"`
	IKELifetime string `json:"ike-lifetime,omitempty"`
}

type TunnelEndpoint struct {
	InterfaceName    string     `json:"interface-name"`
	DSE              string     `json:"dse"`
	IKEVersion       string     `json:"ike-version"`
	IKESA            *IKESA     `json:"ike-sa,omitempty"`
	IPSECSA          *IPSECSA   `json:"ipsec-sa,omitempty"`
	LocalIdentifier  Identifier `json:"local-identifier"`
	RemoteIdentifier Identifier `json:"remote-identifier"`
	Lifetime         *Lifetime  `json:"lifetime,omitempty"`
}

type Lifetime struct {
	SALifetime  string `json:"sa-lifetime,omitempty"`
	IKELifetime string `json:"ike-lifetime,omitempty"`
}

type IKESA struct {
	EncryptionAlgorithms      []string `json:"encryption-algorithms"`
	HashAlgorithms            []string `json:"hash-algorithms"`
	DHGroups                  []string `json:"dh-groups"`
	RekeyLifetime             string   `json:"rekey-lifetime,omitempty"`
	PreSharedKey              string   `json:"pre-shared-key,omitempty"`
	ReauthLifetime            string   `json:"reauth-lifetime,omitempty"`
	DPDDelay                  string   `json:"dpd-delay,omitempty"`
	IKEV1DPDTimeout           string   `json:"ikev1-dpd-timeout,omitempty"`
	IKEInitiator              bool     `json:"ike-initiator,omitempty"`
	AuthType                  string   `json:"auth-type,omitempty"`
	LocalIdentityCertificates string   `json:"local-identity-certificates,omitempty"`
	RemoteCACertificates      []string `json:"remote-ca-certificates,omitempty"`
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

func resourceIPSecPolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	tunnel := &Tunnel{
		Kind:       stringPtr("IPSecPolicy"),
		APIVersion: stringPtr("v1"),
		Meta: TunnelMeta{
			DisplayName: d.Get("display_name").(string),
		},
		Spec: expandSpec(d),
	}

	// Convert the Tunnel struct to JSON
	jsonBytes, err := json.Marshal(tunnel)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error marshalling IPSec Policy: %v", err))
	}

	// Prepare the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/configs/security/v1/tenant/default/ipsecpolicies", config.Server), bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating request: %v", err))
	}

	// Set necessary headers
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error sending request: %v", err))
	}
	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return diag.Errorf("error creating IPSec Policy: API returned status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Decode the response
	var createdTunnel Tunnel
	if err := json.NewDecoder(resp.Body).Decode(&createdTunnel); err != nil {
		return diag.FromErr(fmt.Errorf("error decoding response: %v", err))
	}

	// Set the resource ID
	if createdTunnel.Meta.UUID != nil {
		d.SetId(*createdTunnel.Meta.UUID)
	} else {
		return diag.FromErr(fmt.Errorf("created tunnel UUID is nil"))
	}

	// Update the Terraform state with the returned data
	if err := d.Set("kind", *createdTunnel.Kind); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("api_version", *createdTunnel.APIVersion); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("display_name", createdTunnel.Meta.DisplayName); err != nil {
		return diag.FromErr(err)
	}

	// Use the same flatten function as in Read
	flattenedSpec := flattenSpec(&createdTunnel.Spec, d)
	if err := d.Set("tunnel", flattenedSpec); err != nil {
		return diag.FromErr(err)
	}

	return resourceIPSecPolicyRead(ctx, d, m)
}

func resourceIPSecPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/security/v1/tenant/default/ipsecpolicies/%s", config.Server, d.Id()), nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating request: %v", err))
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})
	response, err := client.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error sending request: %v", err))
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		d.SetId("")
		return nil
	}

	if response.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(response.Body)
		return diag.Errorf("Failed to read IPSec Policy: HTTP %d %s: %s", response.StatusCode, response.Status, bodyBytes)
	}

	var tunnel Tunnel
	if err := json.NewDecoder(response.Body).Decode(&tunnel); err != nil {
		return diag.FromErr(fmt.Errorf("error decoding response: %v", err))
	}

	if err := d.Set("kind", tunnel.Kind); err != nil {
		return diag.FromErr(fmt.Errorf("error setting kind: %v", err))
	}
	if err := d.Set("api_version", tunnel.APIVersion); err != nil {
		return diag.FromErr(fmt.Errorf("error setting api_version: %v", err))
	}
	if err := d.Set("display_name", tunnel.Meta.DisplayName); err != nil {
		return diag.FromErr(fmt.Errorf("error setting display_name: %v", err))
	}

	if err := flattenSpec(&tunnel.Spec, d); err != nil {
		return diag.FromErr(fmt.Errorf("error flattening IPSec Policy: %v", err))
	}

	return nil
}

func resourceIPSecPolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	tunnel := &Tunnel{
		Kind:       stringPtr("IPSecPolicy"),
		APIVersion: stringPtr("v1"),
		Meta: TunnelMeta{
			DisplayName: d.Get("display_name").(string),
		},
		Spec: expandSpec(d),
	}

	// Convert the Tunnel struct to JSON
	jsonBytes, err := json.Marshal(tunnel)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error marshalling IPSec Policy: %v", err))
	}

	// Prepare the HTTP request
	req, err := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s/configs/security/v1/tenant/default/ipsecpolicies/%s", config.Server, d.Id()), bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating request: %v", err))
	}

	// Set necessary headers
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error sending request: %v", err))
	}
	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return diag.Errorf("error updating IPSec Policy: API returned status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var updatedTunnel Tunnel
	if err := json.NewDecoder(resp.Body).Decode(&updatedTunnel); err != nil {
		return diag.FromErr(fmt.Errorf("error decoding response: %v", err))
	}

	// Update the Terraform state with the returned data
	if err := d.Set("kind", *updatedTunnel.Kind); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("api_version", *updatedTunnel.APIVersion); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("display_name", updatedTunnel.Meta.DisplayName); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("tunnel", flattenSpec(&updatedTunnel.Spec, d)); err != nil {
		return diag.FromErr(err)
	}

	return resourceIPSecPolicyRead(ctx, d, m)
}

func resourceIPSecPolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	// Prepare the HTTP request
	req, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s/configs/security/v1/tenant/default/ipsecpolicies/%s", config.Server, d.Id()), nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating delete request: %v", err))
	}

	// Set necessary headers
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error sending delete request: %v", err))
	}
	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return diag.Errorf("error deleting IPSec Policy: API returned status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Clear the ID from the Terraform state
	d.SetId("")

	return nil
}

func resourceIPSecPolicyImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	config := m.(*Config)
	client := config.Client()

	// The import ID is expected to be the resource ID
	resourceID := d.Id()

	// Prepare the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/security/v1/tenant/default/ipsecpolicies/%s", config.Server, resourceID), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating import request: %v", err)
	}

	// Set necessary headers
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending import request: %v", err)
	}
	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("error importing IPSec Policy: API returned status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Decode the response
	var importedTunnel Tunnel
	if err := json.NewDecoder(resp.Body).Decode(&importedTunnel); err != nil {
		return nil, fmt.Errorf("error decoding import response: %v", err)
	}

	// Set the resource data
	if err := d.Set("kind", importedTunnel.Kind); err != nil {
		return nil, err
	}
	if err := d.Set("api_version", importedTunnel.APIVersion); err != nil {
		return nil, err
	}
	if err := d.Set("display_name", importedTunnel.Meta.DisplayName); err != nil {
		return nil, err
	}
	if err := d.Set("tunnel", flattenSpec(&importedTunnel.Spec, d)); err != nil {
		return nil, err
	}

	// The ID is already set by Terraform before calling this function

	return []*schema.ResourceData{d}, nil
}
