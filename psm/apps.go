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
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceApps() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceAppsCreate,
		ReadContext:   resourceAppsRead,
		DeleteContext: resourceAppsDelete,
		UpdateContext: resourceAppsUpdate,
		Importer: &schema.ResourceImporter{
			StateContext: resourceAppsImport,
		},
		Schema: map[string]*schema.Schema{
			"kind": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"api_version": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"display_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: false,
			},
			"meta": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"tenant": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"namespace": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"generation_id": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"resource_version": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"uuid": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
						"labels": {
							Type:     schema.TypeMap,
							Elem:     &schema.Schema{Type: schema.TypeString},
							Optional: true,
							Computed: true,
						},
						"self_link": {
							Type:     schema.TypeString,
							Optional: true,
							Computed: true,
						},
					},
				},
			},
			"spec": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"proto_ports": {
							Type:     schema.TypeList,
							Optional: true,
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
						"apps": {
							Type:     schema.TypeList,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"timeout": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"alg": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"type": {
										Type:     schema.TypeString,
										Required: true,
									},
									"icmp": {
										Type:     schema.TypeList,
										Optional: true,
										MaxItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"type": {
													Type:     schema.TypeString,
													Required: true,
												},
												"code": {
													Type:     schema.TypeString,
													Required: true,
												},
											},
										},
									},
									"dns": {
										Type:     schema.TypeList,
										Optional: true,
										MaxItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"drop_multi_question_packets": {
													Type:     schema.TypeBool,
													Optional: true,
													Default:  false,
												},
												"drop_large_domain_name_packets": {
													Type:     schema.TypeBool,
													Optional: true,
													Default:  false,
												},
												"drop_long_label_packets": {
													Type:     schema.TypeBool,
													Optional: true,
													Default:  false,
												},
												"max_message_length": {
													Type:         schema.TypeInt,
													Optional:     true,
													Default:      512,
													ValidateFunc: validation.IntBetween(1, 8129),
												},
											},
										},
									},
									"ftp": {
										Type:     schema.TypeList,
										Optional: true,
										MaxItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"allow_mismatch_ip_address": {
													Type:     schema.TypeBool,
													Optional: true,
												},
											},
										},
									},
									"sunrpc": {
										Type:     schema.TypeList,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"program_id": {
													Type:     schema.TypeString,
													Required: true,
												},
											},
										},
									},
									"msrpc": {
										Type:     schema.TypeList,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"program_uuid": {
													Type:     schema.TypeString,
													Required: true,
												},
											},
										},
									},
									"tftp": {
										Type:     schema.TypeList,
										Optional: true,
										MaxItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{},
										},
									},
									"rtsp": {
										Type:     schema.TypeList,
										Optional: true,
										MaxItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{},
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

type App struct {
	Kind       interface{} `json:"kind"`
	APIVersion interface{} `json:"api-version"`
	Meta       struct {
		Name            string            `json:"name"`
		Tenant          interface{}       `json:"tenant"`
		Namespace       interface{}       `json:"namespace"`
		GenerationID    interface{}       `json:"generation-id"`
		ResourceVersion interface{}       `json:"resource-version"`
		UUID            interface{}       `json:"uuid"`
		Labels          map[string]string `json:"labels,omitempty"`
		SelfLink        interface{}       `json:"self-link"`
		DisplayName     string            `json:"display-name"`
	} `json:"meta"`
	Spec AppSpec `json:"spec"`
}

type AppSpec struct {
	ProtoPorts []ProtoPorts `json:"proto-ports,omitempty"`
	Apps       []string     `json:"apps,omitempty"`
	Timeout    *string      `json:"timeout,omitempty"`
	ALG        *ALG         `json:"alg,omitempty"`
}

type ProtoPorts struct {
	Protocol string `json:"protocol"`
	Ports    string `json:"ports"`
}

type ALG struct {
	Type   string   `json:"type"`
	ICMP   *ICMP    `json:"icmp,omitempty"`
	DNS    *DNS     `json:"dns,omitempty"`
	FTP    *FTP     `json:"ftp,omitempty"`
	SunRPC []SunRPC `json:"sunrpc,omitempty"`
	MSRPC  []MSRPC  `json:"msrpc,omitempty"`
	TFTP   *TFTP    `json:"tftp,omitempty"`
	RTSP   *RTSP    `json:"rtsp,omitempty"`
}

type ICMP struct {
	Type string `json:"type"`
	Code string `json:"code"`
}

type DNS struct {
	DropMultiQuestionPackets   bool  `json:"drop-multi-question-packets"`
	DropLargeDomainNamePackets bool  `json:"drop-large-domain-name-packets"`
	DropLongLabelPackets       bool  `json:"drop-long-label-packets"`
	MaxMessageLength           int64 `json:"max-message-length"`
}

type FTP struct {
	AllowMismatchIPAddress bool `json:"allow-mismatch-ip-address"`
}

type SunRPC struct {
	ProgramID string  `json:"program-id"`
	Timeout   *string `json:"timeout,omitempty"`
}

type MSRPC struct {
	ProgramUUID string  `json:"program-uuid"`
	Timeout     *string `json:"timeout,omitempty"`
}

type TFTP struct{}
type RTSP struct{}

func resourceAppsCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	app := &App{}
	app.Meta.Tenant = "default"

	app.Meta.DisplayName = d.Get("display_name").(string)

	if spec, ok := d.Get("spec").([]interface{}); ok && len(spec) > 0 {
		specMap := spec[0].(map[string]interface{})

		if protoPorts, ok := specMap["proto_ports"].([]interface{}); ok {
			app.Spec.ProtoPorts = []ProtoPorts{}
			for _, p := range protoPorts {
				port := p.(map[string]interface{})
				protoPort := ProtoPorts{
					Protocol: port["protocol"].(string),
					Ports:    port["ports"].(string),
				}
				app.Spec.ProtoPorts = append(app.Spec.ProtoPorts, protoPort)
			}
		}

		if apps, ok := specMap["apps"].([]interface{}); ok {
			app.Spec.Apps = make([]string, len(apps))
			for i, a := range apps {
				app.Spec.Apps[i] = a.(string)
			}
		}

		// Only set timeout if it's explicitly defined
		if timeout, ok := specMap["timeout"].(string); ok && timeout != "" {
			app.Spec.Timeout = &timeout
		}

		if algList, ok := specMap["alg"].([]interface{}); ok && len(algList) > 0 {
			algMap := algList[0].(map[string]interface{})
			algType := algMap["type"].(string)

			alg := &ALG{
				Type: algType,
			}

			if icmp, ok := algMap["icmp"].([]interface{}); ok && len(icmp) > 0 {
				alg.ICMP = parseICMP(icmp[0].(map[string]interface{}))
			}
			if dns, ok := algMap["dns"].([]interface{}); ok && len(dns) > 0 {
				dnsMap := dns[0].(map[string]interface{})
				alg.DNS = &DNS{}

				if v, ok := dnsMap["drop_multi_question_packets"]; ok {
					alg.DNS.DropMultiQuestionPackets = v.(bool)
				}
				if v, ok := dnsMap["drop_large_domain_name_packets"]; ok {
					alg.DNS.DropLargeDomainNamePackets = v.(bool)
				}
				if v, ok := dnsMap["drop_long_label_packets"]; ok {
					alg.DNS.DropLongLabelPackets = v.(bool)
				}
				if v, ok := dnsMap["max_message_length"]; ok {
					alg.DNS.MaxMessageLength = int64(v.(int))
				}
			}
			if ftp, ok := algMap["ftp"].([]interface{}); ok && len(ftp) > 0 {
				alg.FTP = parseFTP(ftp[0].(map[string]interface{}))
			}
			if sunrpc, ok := algMap["sunrpc"].([]interface{}); ok {
				alg.SunRPC = make([]SunRPC, len(sunrpc))
				for i, s := range sunrpc {
					sunrpcMap := s.(map[string]interface{})
					alg.SunRPC[i] = SunRPC{
						ProgramID: sunrpcMap["program_id"].(string),
					}
				}
			}
			if msrpc, ok := algMap["msrpc"].([]interface{}); ok {
				alg.MSRPC = parseMSRPC(msrpc)
			}

			app.Spec.ALG = alg
		}
	}

	jsonData, err := json.Marshal(app)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/configs/security/v1/tenant/default/apps", config.Server), bytes.NewBuffer(jsonData))
	if err != nil {
		return diag.FromErr(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return diag.Errorf("failed to create app: HTTP %d - %s", resp.StatusCode, string(bodyBytes))
	}

	var createdApp App
	if err := json.NewDecoder(resp.Body).Decode(&createdApp); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdApp.Meta.UUID.(string))

	return resourceAppsRead(ctx, d, m)
}

func resourceAppsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/security/v1/tenant/default/apps/" + d.Id()
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

	if resp.StatusCode == http.StatusNotFound {
		// If the resource doesn't exist, remove it from the state
		d.SetId("")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to read app: HTTP %s", resp.Status)
	}

	app := &App{}
	if err := json.NewDecoder(resp.Body).Decode(app); err != nil {
		return diag.FromErr(err)
	}

	// Set the fields in the state
	d.Set("display_name", app.Meta.DisplayName)
	d.Set("kind", app.Kind)
	d.Set("api_version", app.APIVersion)

	// Set meta
	meta := map[string]interface{}{
		"name":             app.Meta.Name,
		"tenant":           app.Meta.Tenant,
		"namespace":        app.Meta.Namespace,
		"uuid":             app.Meta.UUID,
		"generation_id":    app.Meta.GenerationID,
		"resource_version": app.Meta.ResourceVersion,
		"labels":           app.Meta.Labels,
		"self_link":        app.Meta.SelfLink,
	}
	if err := d.Set("meta", []interface{}{meta}); err != nil {
		return diag.FromErr(err)
	}

	// Set spec
	spec := map[string]interface{}{}

	if len(app.Spec.ProtoPorts) > 0 {
		protoPorts := make([]map[string]interface{}, len(app.Spec.ProtoPorts))
		for i, pp := range app.Spec.ProtoPorts {
			protoPorts[i] = map[string]interface{}{
				"protocol": pp.Protocol,
				"ports":    pp.Ports,
			}
		}
		spec["proto_ports"] = protoPorts
	}

	if len(app.Spec.Apps) > 0 {
		spec["apps"] = app.Spec.Apps
	}

	if app.Spec.Timeout != nil {
		spec["timeout"] = *app.Spec.Timeout
	}

	if app.Spec.ALG != nil {
		algMap := map[string]interface{}{
			"type": app.Spec.ALG.Type,
		}
		// Set ALG fields based on the type
		switch app.Spec.ALG.Type {
		case "icmp":
			if app.Spec.ALG.ICMP != nil {
				algMap["icmp"] = []interface{}{
					map[string]interface{}{
						"type": app.Spec.ALG.ICMP.Type,
						"code": app.Spec.ALG.ICMP.Code,
					},
				}
			}
		case "dns":
			if app.Spec.ALG.DNS != nil {
				algMap["dns"] = []interface{}{
					map[string]interface{}{
						"drop_multi_question_packets":    app.Spec.ALG.DNS.DropMultiQuestionPackets,
						"drop_large_domain_name_packets": app.Spec.ALG.DNS.DropLargeDomainNamePackets,
						"drop_long_label_packets":        app.Spec.ALG.DNS.DropLongLabelPackets,
						"max_message_length":             app.Spec.ALG.DNS.MaxMessageLength,
					},
				}
			}
		case "ftp":
			if app.Spec.ALG.FTP != nil {
				algMap["ftp"] = []interface{}{
					map[string]interface{}{
						"allow_mismatch_ip_address": app.Spec.ALG.FTP.AllowMismatchIPAddress,
					},
				}
			}
		case "sunrpc":
			if len(app.Spec.ALG.SunRPC) > 0 {
				sunrpc := make([]map[string]interface{}, len(app.Spec.ALG.SunRPC))
				for i, s := range app.Spec.ALG.SunRPC {
					sunrpc[i] = map[string]interface{}{
						"program_id": s.ProgramID,
					}
				}
				algMap["sunrpc"] = sunrpc
			}
		case "msrpc":
			if len(app.Spec.ALG.MSRPC) > 0 {
				msrpc := make([]map[string]interface{}, len(app.Spec.ALG.MSRPC))
				for i, m := range app.Spec.ALG.MSRPC {
					msrpc[i] = map[string]interface{}{
						"program_uuid": m.ProgramUUID,
					}
				}
				algMap["msrpc"] = msrpc
			}
		case "tftp":
			algMap["tftp"] = []interface{}{map[string]interface{}{}}
		case "rtsp":
			algMap["rtsp"] = []interface{}{map[string]interface{}{}}
		}
		spec["alg"] = []interface{}{algMap}
	}

	if app.Spec.Timeout != nil {
		spec["timeout"] = *app.Spec.Timeout
	}

	if err := d.Set("spec", []interface{}{spec}); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceAppsUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	app := &App{}

	// Fetch the current state of the app
	url := fmt.Sprintf("%s/configs/security/v1/tenant/default/apps/%s", config.Server, d.Id())
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
		return diag.Errorf("failed to read app: HTTP %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(app); err != nil {
		return diag.FromErr(err)
	}

	if d.HasChange("display_name") {
		app.Meta.DisplayName = d.Get("display_name").(string)
	}

	if d.HasChange("spec") {
		if spec, ok := d.Get("spec").([]interface{}); ok && len(spec) > 0 {
			specMap := spec[0].(map[string]interface{})

			// Reset the spec
			app.Spec = AppSpec{}

			if protoPorts, ok := specMap["proto_ports"].([]interface{}); ok {
				app.Spec.ProtoPorts = []ProtoPorts{}
				for _, p := range protoPorts {
					port := p.(map[string]interface{})
					protoPort := ProtoPorts{
						Protocol: port["protocol"].(string),
						Ports:    port["ports"].(string),
					}
					app.Spec.ProtoPorts = append(app.Spec.ProtoPorts, protoPort)
				}
			}

			if apps, ok := specMap["apps"].([]interface{}); ok {
				app.Spec.Apps = make([]string, len(apps))
				for i, a := range apps {
					app.Spec.Apps[i] = a.(string)
				}
			}

			// Only set timeout if it's explicitly defined
			if timeout, ok := specMap["timeout"].(string); ok && timeout != "" {
				app.Spec.Timeout = &timeout
			}

			if algList, ok := specMap["alg"].([]interface{}); ok && len(algList) > 0 {
				algMap := algList[0].(map[string]interface{})
				algType := algMap["type"].(string)

				alg := &ALG{
					Type: algType,
				}

				// Handle ALG fields based on type
				switch algType {
				case "icmp":
					if icmp, ok := algMap["icmp"].([]interface{}); ok && len(icmp) > 0 {
						alg.ICMP = parseICMP(icmp[0].(map[string]interface{}))
					}
				case "dns":
					if dns, ok := algMap["dns"].([]interface{}); ok && len(dns) > 0 {
						alg.DNS = parseDNS(dns[0].(map[string]interface{}))
					}
				case "ftp":
					if ftp, ok := algMap["ftp"].([]interface{}); ok && len(ftp) > 0 {
						alg.FTP = parseFTP(ftp[0].(map[string]interface{}))
					}
				case "sunrpc":
					if sunrpc, ok := algMap["sunrpc"].([]interface{}); ok {
						alg.SunRPC = parseSunRPC(sunrpc)
					}
				case "msrpc":
					if msrpc, ok := algMap["msrpc"].([]interface{}); ok {
						alg.MSRPC = parseMSRPC(msrpc)
					}
				case "tftp":
					alg.TFTP = &TFTP{}
				case "rtsp":
					alg.RTSP = &RTSP{}
				}

				app.Spec.ALG = alg
			}
		}
	}

	jsonData, err := json.Marshal(app)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err = http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return diag.FromErr(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err = client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return diag.Errorf("failed to update app: HTTP %d - %s", resp.StatusCode, string(bodyBytes))
	}

	return resourceAppsRead(ctx, d, m)
}

func resourceAppsDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	// Construct the URL for the app based on its UUID
	url := config.Server + "/configs/security/v1/tenant/default/apps/" + d.Id()

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return diag.FromErr(err)
	}

	// Set SID cookie for authentication
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to delete app: HTTP %s", resp.Status)
	}

	// Clear the resource ID as it's been deleted from the PSM server.
	d.SetId("")

	return nil
}

func parseICMP(icmpMap map[string]interface{}) *ICMP {
	return &ICMP{
		Type: icmpMap["type"].(string),
		Code: icmpMap["code"].(string),
	}
}

func parseDNS(dnsMap map[string]interface{}) *DNS {
	return &DNS{
		DropMultiQuestionPackets:   dnsMap["drop_multi_question_packets"].(bool),
		DropLargeDomainNamePackets: dnsMap["drop_large_domain_name_packets"].(bool),
		DropLongLabelPackets:       dnsMap["drop_long_label_packets"].(bool),
		MaxMessageLength:           dnsMap["max_message_length"].(int64),
	}
}

func parseFTP(ftpMap map[string]interface{}) *FTP {
	return &FTP{
		AllowMismatchIPAddress: ftpMap["allow_mismatch_ip_address"].(bool),
	}
}

func parseSunRPC(sunrpc []interface{}) []SunRPC {
	var sunrpcs []SunRPC
	for _, s := range sunrpc {
		sunrpcMap := s.(map[string]interface{})
		sunrpcs = append(sunrpcs, SunRPC{
			ProgramID: sunrpcMap["program_id"].(string),
		})
	}
	return sunrpcs
}

func parseMSRPC(msrpc []interface{}) []MSRPC {
	var msrpcs []MSRPC
	for _, m := range msrpc {
		msrpcMap := m.(map[string]interface{})
		msrpcs = append(msrpcs, MSRPC{
			ProgramUUID: msrpcMap["program_uuid"].(string),
		})
	}
	return msrpcs
}
func resourceAppsImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	config := m.(*Config)
	client := config.Client()

	// The ID passed will be the name of the App
	name := d.Id()

	// Construct the URL for fetching the App
	url := fmt.Sprintf("%s/configs/security/v1/tenant/default/apps/%s", config.Server, name)

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
		return nil, fmt.Errorf("failed to import app: HTTP %s", resp.Status)
	}

	app := &App{}
	if err := json.NewDecoder(resp.Body).Decode(app); err != nil {
		return nil, err
	}

	// Set the ID to the UUID returned by the API
	d.SetId(app.Meta.UUID.(string))

	// Call Read to populate the rest of the data
	diags := resourceAppsRead(ctx, d, m)
	if diags.HasError() {
		return nil, fmt.Errorf("failed to read imported app: %v", diags)
	}

	return []*schema.ResourceData{d}, nil
}
