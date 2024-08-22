package psm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceAuthnPolicy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceAuthnPolicyCreate,
		ReadContext:   resourceAuthnPolicyRead,
		UpdateContext: resourceAuthnPolicyUpdate,
		DeleteContext: resourceAuthnPolicyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceAuthnPolicyImport,
		},
		Schema: map[string]*schema.Schema{
			"token_expiry": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"authenticator_order": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
					ValidateFunc: validation.StringInSlice([]string{
						"local", "ldap", "radius",
					}, false),
				},
			},
			"local": {
				Type:     schema.TypeList,
				MaxItems: 1,
				Optional: true,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"password_length": {
							Type:         schema.TypeInt,
							Optional:     true,
							Default:      9,
							ValidateFunc: validation.IntAtLeast(3),
						},
						"allowed_failed_login_attempts": {
							Type:     schema.TypeInt,
							Optional: true,
							Default:  10,
						},
						"failed_login_attempts_duration": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "15m",
						},
					},
				},
			},
			"ldap": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"base_dn": {
							Type:     schema.TypeString,
							Required: true,
						},
						"bind_dn": {
							Type:     schema.TypeString,
							Required: true,
						},
						// Workaround, no API return value
						"bind_password": {
							Type:      schema.TypeString,
							Optional:  true,
							Sensitive: true,
							Computed:  true,
							DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
								return new == ""
							},
						},
						"attribute_mapping": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Required: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"user": {
										Type:     schema.TypeString,
										Required: true,
									},
									"user_object_class": {
										Type:     schema.TypeString,
										Required: true,
									},
									"tenant": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"group": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"group_object_class": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"email": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"fullname": {
										Type:     schema.TypeString,
										Optional: true,
									},
								},
							},
						},
						"servers": {
							Type:     schema.TypeList,
							Required: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"url": {
										Type:     schema.TypeString,
										Required: true,
									},
									"tls_options": {
										Type:     schema.TypeList,
										MaxItems: 1,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"start_tls": {
													Type:     schema.TypeBool,
													Optional: true,
												},
												"skip_server_cert_verification": {
													Type:     schema.TypeBool,
													Optional: true,
												},
												"server_name": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"trusted_certs": {
													Type:     schema.TypeString,
													Optional: true,
												},
											},
										},
									},
								},
							},
						},
						"tag": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"skip_nested_groups": {
							Type:     schema.TypeBool,
							Optional: true,
						},
					},
				},
			},
			"radius": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"nas_id": {
							Type:     schema.TypeString,
							Required: true,
						},
						"servers": {
							Type:     schema.TypeList,
							Required: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"url": {
										Type:     schema.TypeString,
										Required: true,
									},
									"auth_method": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"trusted_certs": {
										Type:     schema.TypeString,
										Optional: true,
									},
									// Workaround, no API return value
									"secret": {
										Type:      schema.TypeString,
										Optional:  true,
										Sensitive: true,
										Computed:  true,
										DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
											return new == ""
										},
									},
								},
							},
						},
						"tag": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
		},
	}
}

type AuthnPolicy struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api-version"`
	Meta       struct {
		Name            string      `json:"name"`
		Tenant          interface{} `json:"tenant"`
		Namespace       interface{} `json:"namespace"`
		GenerationID    string      `json:"generation-id"`
		ResourceVersion string      `json:"resource-version"`
		UUID            string      `json:"uuid"`
		Labels          interface{} `json:"labels"`
		SelfLink        string      `json:"self-link"`
		DisplayName     interface{} `json:"display-name"`
	} `json:"meta"`
	Spec struct {
		Authenticators struct {
			AuthenticatorOrder []string `json:"authenticator-order"`
			LDAP               struct {
				Domains []LDAPDomain `json:"domains"`
			} `json:"ldap"`
			Local struct {
				PasswordLength              int    `json:"password-length"`
				AllowedFailedLoginAttempts  int    `json:"allowed-failed-login-attempts"`
				FailedLoginAttemptsDuration string `json:"failed-login-attempts-duration"`
			} `json:"local"`
			Radius struct {
				Domains []RadiusDomain `json:"domains"`
			} `json:"radius"`
		} `json:"authenticators"`
		Secret      interface{} `json:"secret"`
		TokenExpiry string      `json:"token-expiry"`
	} `json:"spec"`
	Status struct {
		LDAPServers   []interface{} `json:"ldap-servers"`
		RadiusServers []interface{} `json:"radius-servers"`
	} `json:"status"`
}

type LDAPDomain struct {
	BaseDN           string           `json:"base-dn"`
	BindDN           string           `json:"bind-dn"`
	BindPassword     string           `json:"bind-password"`
	AttributeMapping AttributeMapping `json:"attribute-mapping"`
	Servers          []LDAPServer     `json:"servers"`
	Tag              interface{}      `json:"tag"`
	SkipNestedGroups interface{}      `json:"skip-nested-groups"`
}

type AttributeMapping struct {
	User             string `json:"user"`
	UserObjectClass  string `json:"user-object-class"`
	Tenant           string `json:"tenant"`
	Group            string `json:"group"`
	GroupObjectClass string `json:"group-object-class"`
	Email            string `json:"email"`
	Fullname         string `json:"fullname"`
}

type LDAPServer struct {
	URL        string     `json:"url"`
	TLSOptions TLSOptions `json:"tls-options"`
}

type TLSOptions struct {
	StartTLS                   bool        `json:"start-tls"`
	SkipServerCertVerification bool        `json:"skip-server-cert-verification"`
	ServerName                 interface{} `json:"server-name"`
	TrustedCerts               interface{} `json:"trusted-certs"`
}

type RadiusDomain struct {
	NasID   string         `json:"nas-id"`
	Servers []RadiusServer `json:"servers"`
	Tag     interface{}    `json:"tag"`
}

type RadiusServer struct {
	URL          string      `json:"url"`
	Secret       interface{} `json:"secret"`
	AuthMethod   string      `json:"auth-method"`
	TrustedCerts interface{} `json:"trusted-certs"`
}

func resourceAuthnPolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	authnPolicy := &AuthnPolicy{
		Kind:       "AuthenticationPolicy",
		APIVersion: "v1",
	}

	// Set token expiry
	if v, ok := d.GetOk("token_expiry"); ok {
		authnPolicy.Spec.TokenExpiry = v.(string)
	}

	// Set authenticator order
	if v, ok := d.GetOk("authenticator_order"); ok {
		authnPolicy.Spec.Authenticators.AuthenticatorOrder = expandStringList(v.([]interface{}))
	}

	// Set local authenticator
	if v, ok := d.GetOk("local"); ok {
		local := v.([]interface{})[0].(map[string]interface{})
		authnPolicy.Spec.Authenticators.Local.PasswordLength = local["password_length"].(int)
		authnPolicy.Spec.Authenticators.Local.AllowedFailedLoginAttempts = local["allowed_failed_login_attempts"].(int)
		authnPolicy.Spec.Authenticators.Local.FailedLoginAttemptsDuration = local["failed_login_attempts_duration"].(string)
	}

	// Set LDAP domains
	if v, ok := d.GetOk("ldap"); ok {
		ldapDomains := v.([]interface{})
		authnPolicy.Spec.Authenticators.LDAP.Domains = make([]LDAPDomain, len(ldapDomains))
		for i, domain := range ldapDomains {
			d := domain.(map[string]interface{})
			ldapDomain := LDAPDomain{
				BaseDN:       d["base_dn"].(string),
				BindDN:       d["bind_dn"].(string),
				BindPassword: d["bind_password"].(string),
				AttributeMapping: AttributeMapping{
					User:             d["attribute_mapping"].([]interface{})[0].(map[string]interface{})["user"].(string),
					UserObjectClass:  d["attribute_mapping"].([]interface{})[0].(map[string]interface{})["user_object_class"].(string),
					Tenant:           d["attribute_mapping"].([]interface{})[0].(map[string]interface{})["tenant"].(string),
					Group:            d["attribute_mapping"].([]interface{})[0].(map[string]interface{})["group"].(string),
					GroupObjectClass: d["attribute_mapping"].([]interface{})[0].(map[string]interface{})["group_object_class"].(string),
					Email:            d["attribute_mapping"].([]interface{})[0].(map[string]interface{})["email"].(string),
					Fullname:         d["attribute_mapping"].([]interface{})[0].(map[string]interface{})["fullname"].(string),
				},
				Servers:          make([]LDAPServer, 0),
				Tag:              nil,
				SkipNestedGroups: nil,
			}

			for _, server := range d["servers"].([]interface{}) {
				s := server.(map[string]interface{})
				serverStruct := LDAPServer{
					URL: s["url"].(string),
					TLSOptions: TLSOptions{
						StartTLS:                   s["tls_options"].([]interface{})[0].(map[string]interface{})["start_tls"].(bool),
						SkipServerCertVerification: s["tls_options"].([]interface{})[0].(map[string]interface{})["skip_server_cert_verification"].(bool),
						ServerName:                 nil,
						TrustedCerts:               nil,
					},
				}
				ldapDomain.Servers = append(ldapDomain.Servers, serverStruct)
			}

			authnPolicy.Spec.Authenticators.LDAP.Domains[i] = ldapDomain
		}
	}

	// Set RADIUS domains
	if v, ok := d.GetOk("radius"); ok {
		radiusDomains := v.([]interface{})
		authnPolicy.Spec.Authenticators.Radius.Domains = make([]RadiusDomain, len(radiusDomains))
		for i, domain := range radiusDomains {
			d := domain.(map[string]interface{})
			radiusDomain := RadiusDomain{
				NasID:   d["nas_id"].(string),
				Servers: make([]RadiusServer, 0),
				Tag:     nil,
			}

			for _, server := range d["servers"].([]interface{}) {
				s := server.(map[string]interface{})
				radiusDomain.Servers = append(radiusDomain.Servers, RadiusServer{
					URL:          s["url"].(string),
					Secret:       nil,
					AuthMethod:   s["auth_method"].(string),
					TrustedCerts: nil,
				})
			}

			authnPolicy.Spec.Authenticators.Radius.Domains[i] = radiusDomain
		}
	}

	jsonData, err := json.Marshal(authnPolicy)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s/configs/auth/v1/authn-policy", config.Server), bytes.NewBuffer(jsonData))
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
		return diag.Errorf("failed to create authentication policy: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var createdPolicy AuthnPolicy
	if err := json.NewDecoder(res.Body).Decode(&createdPolicy); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdPolicy.Meta.UUID)

	return resourceAuthnPolicyRead(ctx, d, m)
}

func resourceAuthnPolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/auth/v1/authn-policy", config.Server), nil)
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
		return diag.Errorf("failed to read authentication policy: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var authnPolicy AuthnPolicy
	if err := json.NewDecoder(res.Body).Decode(&authnPolicy); err != nil {
		return diag.FromErr(err)
	}

	d.Set("token_expiry", authnPolicy.Spec.TokenExpiry)
	d.Set("authenticator_order", authnPolicy.Spec.Authenticators.AuthenticatorOrder)

	// Set local authenticator settings
	localConfig := []map[string]interface{}{
		{
			"password_length":                authnPolicy.Spec.Authenticators.Local.PasswordLength,
			"allowed_failed_login_attempts":  authnPolicy.Spec.Authenticators.Local.AllowedFailedLoginAttempts,
			"failed_login_attempts_duration": authnPolicy.Spec.Authenticators.Local.FailedLoginAttemptsDuration,
		},
	}
	if err := d.Set("local", localConfig); err != nil {
		return diag.FromErr(err)
	}

	// Set LDAP domains
	ldapDomains := make([]map[string]interface{}, len(authnPolicy.Spec.Authenticators.LDAP.Domains))
	for i, domain := range authnPolicy.Spec.Authenticators.LDAP.Domains {
		ldapDomains[i] = map[string]interface{}{
			"base_dn":       domain.BaseDN,
			"bind_dn":       domain.BindDN,
			"bind_password": d.Get(fmt.Sprintf("ldap.%d.bind_password", i)),
			"attribute_mapping": []map[string]interface{}{
				{
					"user":               domain.AttributeMapping.User,
					"user_object_class":  domain.AttributeMapping.UserObjectClass,
					"tenant":             domain.AttributeMapping.Tenant,
					"group":              domain.AttributeMapping.Group,
					"group_object_class": domain.AttributeMapping.GroupObjectClass,
					"email":              domain.AttributeMapping.Email,
					"fullname":           domain.AttributeMapping.Fullname,
				},
			},
			"tag":                domain.Tag,
			"skip_nested_groups": domain.SkipNestedGroups,
		}

		servers := make([]map[string]interface{}, len(domain.Servers))
		for j, server := range domain.Servers {
			servers[j] = map[string]interface{}{
				"url": server.URL,
				"tls_options": []map[string]interface{}{
					{
						"start_tls":                     server.TLSOptions.StartTLS,
						"skip_server_cert_verification": server.TLSOptions.SkipServerCertVerification,
						"server_name":                   server.TLSOptions.ServerName,
						"trusted_certs":                 server.TLSOptions.TrustedCerts,
					},
				},
			}
		}
		ldapDomains[i]["servers"] = servers
	}
	if err := d.Set("ldap", ldapDomains); err != nil {
		return diag.FromErr(err)
	}

	// Set RADIUS domains
	radiusDomains := make([]map[string]interface{}, len(authnPolicy.Spec.Authenticators.Radius.Domains))
	for i, domain := range authnPolicy.Spec.Authenticators.Radius.Domains {
		radiusDomains[i] = map[string]interface{}{
			"nas_id": domain.NasID,
			"tag":    domain.Tag,
		}

		servers := make([]map[string]interface{}, len(domain.Servers))
		for j, server := range domain.Servers {
			servers[j] = map[string]interface{}{
				"url":         server.URL,
				"auth_method": server.AuthMethod,
				"secret":      d.Get(fmt.Sprintf("radius.%d.servers.%d.secret", i, j)),
			}
		}
		radiusDomains[i]["servers"] = servers
	}
	if err := d.Set("radius", radiusDomains); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceAuthnPolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	// First, get the current policy
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/auth/v1/authn-policy", config.Server), nil)
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
		return diag.Errorf("failed to get current authentication policy: HTTP %d", res.StatusCode)
	}

	var currentPolicy AuthnPolicy
	if err := json.NewDecoder(res.Body).Decode(&currentPolicy); err != nil {
		return diag.FromErr(err)
	}

	// Log the current policy
	currentPolicyJSON, _ := json.MarshalIndent(currentPolicy, "", "  ")
	tflog.Info(ctx, "Current authentication policy", map[string]interface{}{
		"current_policy": string(currentPolicyJSON),
	})

	// Start with the current policy and update only changed fields
	updatedPolicy := currentPolicy

	if d.HasChange("token_expiry") {
		updatedPolicy.Spec.TokenExpiry = d.Get("token_expiry").(string)
	}

	if d.HasChange("authenticator_order") {
		updatedPolicy.Spec.Authenticators.AuthenticatorOrder = expandStringList(d.Get("authenticator_order").([]interface{}))
	}

	if d.HasChange("local") {
		local := d.Get("local").([]interface{})[0].(map[string]interface{})
		updatedPolicy.Spec.Authenticators.Local.PasswordLength = local["password_length"].(int)
		updatedPolicy.Spec.Authenticators.Local.AllowedFailedLoginAttempts = local["allowed_failed_login_attempts"].(int)
		updatedPolicy.Spec.Authenticators.Local.FailedLoginAttemptsDuration = local["failed_login_attempts_duration"].(string)
	}

	if d.HasChange("ldap") {
		ldapDomains := d.Get("ldap").([]interface{})
		updatedPolicy.Spec.Authenticators.LDAP.Domains = make([]LDAPDomain, len(ldapDomains))
		for i, domain := range ldapDomains {
			d := domain.(map[string]interface{})
			ldapDomain := LDAPDomain{
				BaseDN:       d["base_dn"].(string),
				BindDN:       d["bind_dn"].(string),
				BindPassword: d["bind_password"].(string),
				AttributeMapping: AttributeMapping{
					User:             d["attribute_mapping"].([]interface{})[0].(map[string]interface{})["user"].(string),
					UserObjectClass:  d["attribute_mapping"].([]interface{})[0].(map[string]interface{})["user_object_class"].(string),
					Tenant:           d["attribute_mapping"].([]interface{})[0].(map[string]interface{})["tenant"].(string),
					Group:            d["attribute_mapping"].([]interface{})[0].(map[string]interface{})["group"].(string),
					GroupObjectClass: d["attribute_mapping"].([]interface{})[0].(map[string]interface{})["group_object_class"].(string),
					Email:            d["attribute_mapping"].([]interface{})[0].(map[string]interface{})["email"].(string),
					Fullname:         d["attribute_mapping"].([]interface{})[0].(map[string]interface{})["fullname"].(string),
				},
				Servers:          make([]LDAPServer, 0),
				Tag:              d["tag"],
				SkipNestedGroups: d["skip_nested_groups"],
			}

			for _, server := range d["servers"].([]interface{}) {
				s := server.(map[string]interface{})
				serverStruct := LDAPServer{
					URL: s["url"].(string),
					TLSOptions: TLSOptions{
						StartTLS:                   s["tls_options"].([]interface{})[0].(map[string]interface{})["start_tls"].(bool),
						SkipServerCertVerification: s["tls_options"].([]interface{})[0].(map[string]interface{})["skip_server_cert_verification"].(bool),
						ServerName:                 s["tls_options"].([]interface{})[0].(map[string]interface{})["server_name"],
						TrustedCerts:               s["tls_options"].([]interface{})[0].(map[string]interface{})["trusted_certs"],
					},
				}
				ldapDomain.Servers = append(ldapDomain.Servers, serverStruct)
			}

			updatedPolicy.Spec.Authenticators.LDAP.Domains[i] = ldapDomain
		}
	}

	if d.HasChange("radius") {
		radiusDomains := d.Get("radius").([]interface{})
		updatedPolicy.Spec.Authenticators.Radius.Domains = make([]RadiusDomain, len(radiusDomains))
		for i, domain := range radiusDomains {
			d := domain.(map[string]interface{})
			radiusDomain := RadiusDomain{
				NasID:   d["nas_id"].(string),
				Servers: make([]RadiusServer, 0),
				Tag:     d["tag"],
			}

			for _, server := range d["servers"].([]interface{}) {
				s := server.(map[string]interface{})
				radiusDomain.Servers = append(radiusDomain.Servers, RadiusServer{
					URL:          s["url"].(string),
					Secret:       s["secret"],
					AuthMethod:   s["auth_method"].(string),
					TrustedCerts: s["trusted_certs"],
				})
			}

			updatedPolicy.Spec.Authenticators.Radius.Domains[i] = radiusDomain
		}
	}

	// Log the updated policy before sending
	updatedPolicyJSON, _ := json.MarshalIndent(updatedPolicy, "", "  ")
	tflog.Info(ctx, "Updated authentication policy to be sent", map[string]interface{}{
		"updated_policy": string(updatedPolicyJSON),
	})

	jsonData, err := json.Marshal(updatedPolicy)
	if err != nil {
		return diag.FromErr(err)
	}

	updateReq, err := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s/configs/auth/v1/authn-policy", config.Server), bytes.NewBuffer(jsonData))
	if err != nil {
		return diag.FromErr(err)
	}

	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	updateRes, err := client.Do(updateReq)
	if err != nil {
		return diag.FromErr(err)
	}
	defer updateRes.Body.Close()

	if updateRes.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(updateRes.Body)
		if err != nil {
			return diag.Errorf("failed to read error response body: %v", err)
		}
		return diag.Errorf("failed to update authentication policy: HTTP %d - %s", updateRes.StatusCode, string(bodyBytes))
	}

	// Log the response
	var responsePolicy AuthnPolicy
	if err := json.NewDecoder(updateRes.Body).Decode(&responsePolicy); err != nil {
		return diag.FromErr(err)
	}
	responsePolicyJSON, _ := json.MarshalIndent(responsePolicy, "", "  ")
	tflog.Info(ctx, "Response from update request", map[string]interface{}{
		"response_policy": string(responsePolicyJSON),
	})

	return resourceAuthnPolicyRead(ctx, d, m)
}

func resourceAuthnPolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	// First, read the current policy
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/auth/v1/authn-policy", config.Server), nil)
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
			return diag.Errorf("failed to read authentication policy: %v", err)
		}
		return diag.Errorf("failed to read authentication policy: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var authnPolicy AuthnPolicy
	if err := json.NewDecoder(res.Body).Decode(&authnPolicy); err != nil {
		return diag.FromErr(err)
	}

	// Remove RADIUS and LDAP configurations
	authnPolicy.Spec.Authenticators.LDAP.Domains = nil
	authnPolicy.Spec.Authenticators.Radius.Domains = nil

	// Remove LDAP and RADIUS from authenticator order if present
	newOrder := make([]string, 0)
	for _, auth := range authnPolicy.Spec.Authenticators.AuthenticatorOrder {
		if auth != "ldap" && auth != "radius" {
			newOrder = append(newOrder, auth)
		}
	}
	authnPolicy.Spec.Authenticators.AuthenticatorOrder = newOrder

	// Prepare the update request
	jsonData, err := json.Marshal(authnPolicy)
	if err != nil {
		return diag.FromErr(err)
	}

	updateReq, err := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s/configs/auth/v1/authn-policy", config.Server), bytes.NewBuffer(jsonData))
	if err != nil {
		return diag.FromErr(err)
	}

	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	updateRes, err := client.Do(updateReq)
	if err != nil {
		return diag.FromErr(err)
	}
	defer updateRes.Body.Close()

	if updateRes.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(updateRes.Body)
		if err != nil {
			return diag.Errorf("failed to read error response body: %v", err)
		}
		return diag.Errorf("failed to update authentication policy: HTTP %d - %s", updateRes.StatusCode, string(bodyBytes))
	}

	// The resource ID remains the same as we're not fully deleting the policy
	// but we need to clear the LDAP and RADIUS configurations from the state
	d.Set("ldap", nil)
	d.Set("radius", nil)

	return nil
}

func resourceAuthnPolicyImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	// Since there's only one authentication policy per system, we don't need an ID for import
	// We'll use a placeholder ID
	d.SetId("authn-policy")

	// Read the authentication policy from the API
	diags := resourceAuthnPolicyRead(ctx, d, m)
	if diags.HasError() {
		return nil, fmt.Errorf("failed to read authentication policy during import: %v", diags[0].Summary)
	}

	return []*schema.ResourceData{d}, nil
}
