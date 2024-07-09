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
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceApps() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceAppsCreate,
		ReadContext:   resourceAppsRead,
		DeleteContext: resourceAppsDelete,
		UpdateContext: resourceAppsUpdate,
		Schema: map[string]*schema.Schema{
			"kind": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"api_version": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"display_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
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
							Default:  "60s",
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
		Labels          map[string]string `json:"labels"`
		SelfLink        interface{}       `json:"self-link"`
		DisplayName     string            `json:"display-name"`
	} `json:"meta"`
	Spec struct {
		ProtoPorts []ProtoPorts `json:"proto-ports"`
		Apps       []string     `json:"apps"`
		Timeout    *string      `json:"timeout,omitempty"`
		ALG        *ALG         `json:"alg,omitempty"`
	} `json:"spec"`
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

	if spec, ok := d.Get("spec").([]interface{}); ok && len(spec) > 0 {
		specMap := spec[0].(map[string]interface{})

		if protoPorts, ok := specMap["proto_ports"].([]interface{}); ok {
			for _, p := range protoPorts {
				port := p.(map[string]interface{})
				protoPort := ProtoPorts{}
				if protocol, ok := port["protocol"].(string); ok {
					protoPort.Protocol = protocol
				}
				if ports, ok := port["ports"].(string); ok {
					protoPort.Ports = ports
				}

				app.Spec.ProtoPorts = append(app.Spec.ProtoPorts, protoPort)
			}
		}
		if apps, ok := specMap["apps"].([]interface{}); ok {
			for _, a := range apps {
				app.Spec.Apps = append(app.Spec.Apps, a.(string))
			}
		}
		if algList, ok := specMap["alg"].([]interface{}); ok && len(algList) > 0 {
			algMap := algList[0].(map[string]interface{})
			algType := algMap["type"].(string)

			// Only set timeout for RPC ALGs
			if algType == "sunrpc" || algType == "msrpc" {
				if timeout, ok := specMap["timeout"].(string); ok {
					timeoutPtr := timeout
					app.Spec.Timeout = &timeoutPtr
				}
			}

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

	app.Meta.DisplayName = d.Get("display_name").(string)

	// Convert the API struct to JSON.
	jsonBytes, err := json.Marshal(app)
	if err != nil {
		return diag.FromErr(err)
	}
	fmt.Println(string(jsonBytes))

	req, err := http.NewRequestWithContext(ctx, "POST", config.Server+"/configs/security/v1/tenant/default/apps", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	// Log the request details
	log.Printf("[DEBUG] Request method: %s", req.Method)
	log.Printf("[DEBUG] Request URL: %s", req.URL.String())
	log.Printf("[DEBUG] Request body: %s", jsonBytes)

	// Set SID cookie for authentication
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("failed to create app: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		// Added for additional debug if the JSON we send to the PSM server is invalid.
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "App creation failed",
				Detail:   errMsg,
			},
		}
	}

	responseBody := &App{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return diag.FromErr(err)
	}

	// Set the Terraform resource ID to the UUID returned by the API.
	d.SetId(responseBody.Meta.UUID.(string))

	return append(diag.Diagnostics{}, resourceAppsRead(ctx, d, m)...)
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

	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to read app: HTTP %s", resp.Status)
	}

	app := &App{}
	if err := json.NewDecoder(resp.Body).Decode(app); err != nil {
		return diag.FromErr(err)
	}

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
	d.Set("meta", []interface{}{meta})

	d.Set("display_name", app.Meta.DisplayName)
	d.Set("kind", app.Kind)
	d.Set("api_version", app.APIVersion)

	spec := make(map[string]interface{})

	protoPorts := make([]map[string]interface{}, len(app.Spec.ProtoPorts))
	for i, pp := range app.Spec.ProtoPorts {
		protoPorts[i] = map[string]interface{}{
			"protocol": pp.Protocol,
			"ports":    pp.Ports,
		}
	}
	spec["proto_ports"] = protoPorts
	spec["apps"] = app.Spec.Apps

	if app.Spec.ALG != nil {
		algMap := map[string]interface{}{
			"type": app.Spec.ALG.Type,
		}
		if app.Spec.ALG.ICMP != nil {
			algMap["icmp"] = []interface{}{
				map[string]interface{}{
					"type": app.Spec.ALG.ICMP.Type,
					"code": app.Spec.ALG.ICMP.Code,
				},
			}
		}
		if app.Spec.ALG != nil && app.Spec.ALG.DNS != nil {
			dnsMap := map[string]interface{}{}
			if app.Spec.ALG.DNS.DropMultiQuestionPackets {
				dnsMap["drop_multi_question_packets"] = true
			}
			if app.Spec.ALG.DNS.DropLargeDomainNamePackets {
				dnsMap["drop_large_domain_name_packets"] = true
			}
			if app.Spec.ALG.DNS.DropLongLabelPackets {
				dnsMap["drop_long_label_packets"] = true
			}
			if app.Spec.ALG.DNS.MaxMessageLength != 0 {
				dnsMap["max_message_length"] = app.Spec.ALG.DNS.MaxMessageLength
			}
			if app.Spec.ALG.TFTP != nil {
				algMap["tftp"] = []interface{}{map[string]interface{}{}}
			}
			if app.Spec.ALG.RTSP != nil {
				algMap["rtsp"] = []interface{}{map[string]interface{}{}}
			}

			algMap["dns"] = []interface{}{dnsMap}
		}

		if app.Spec.Timeout != nil {
			spec["timeout"] = *app.Spec.Timeout
		}

		if app.Spec.ALG.FTP != nil {
			algMap["ftp"] = []interface{}{
				map[string]interface{}{
					"allow_mismatch_ip_address": app.Spec.ALG.FTP.AllowMismatchIPAddress,
				},
			}
		}
		if len(app.Spec.ALG.SunRPC) > 0 {
			sunrpc := make([]map[string]interface{}, len(app.Spec.ALG.SunRPC))
			for i, s := range app.Spec.ALG.SunRPC {
				sunrpc[i] = map[string]interface{}{
					"program_id": s.ProgramID,
				}
			}
			algMap["sunrpc"] = sunrpc
		}
		if len(app.Spec.ALG.MSRPC) > 0 {
			msrpc := make([]map[string]interface{}, len(app.Spec.ALG.MSRPC))
			for i, m := range app.Spec.ALG.MSRPC {
				msrpc[i] = map[string]interface{}{
					"program_uuid": m.ProgramUUID,
					"timeout":      m.Timeout,
				}
			}
			algMap["msrpc"] = msrpc
		}
		spec["alg"] = []interface{}{algMap}
	}

	d.Set("spec", []interface{}{spec})

	return nil
}

func resourceAppsUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	// Fetch the current state of the app
	app := &App{}
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
	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to read app: HTTP %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(app); err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Current app state: %+v", app)

	// Update fields that have changed
	if d.HasChange("kind") {
		app.Kind = d.Get("kind")
	}
	if d.HasChange("api_version") {
		app.APIVersion = d.Get("api_version")
	}
	if d.HasChange("display_name") {
		app.Meta.DisplayName = d.Get("display_name").(string)
	}

	if d.HasChange("meta") {
		if meta, ok := d.GetOk("meta"); ok {
			metaList := meta.([]interface{})
			if len(metaList) > 0 {
				metaMap := metaList[0].(map[string]interface{})
				app.Meta.Name = metaMap["name"].(string)
				app.Meta.Tenant = metaMap["tenant"]
				app.Meta.Namespace = metaMap["namespace"]
				app.Meta.GenerationID = metaMap["generation_id"]
				app.Meta.ResourceVersion = metaMap["resource_version"]
				app.Meta.UUID = metaMap["uuid"]

				if labels, ok := metaMap["labels"].(map[string]interface{}); ok {
					app.Meta.Labels = make(map[string]string)
					for k, v := range labels {
						app.Meta.Labels[k] = v.(string)
					}
				}

				app.Meta.SelfLink = metaMap["self_link"]
			}
		}
	}

	if d.HasChange("spec") {
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

			if algList, ok := specMap["alg"].([]interface{}); ok && len(algList) > 0 {
				algMap := algList[0].(map[string]interface{})
				algType := algMap["type"].(string)

				alg := &ALG{
					Type: algType,
				}

				// Only set timeout for RPC ALGs
				if algType == "sunrpc" || algType == "msrpc" {
					if timeout, ok := specMap["timeout"].(string); ok {
						app.Spec.Timeout = &timeout
					}
				} else {
					app.Spec.Timeout = nil // Clear timeout for non-RPC ALGs
				}

				switch alg.Type {
				case "icmp":
					if icmp, ok := algMap["icmp"].([]interface{}); ok && len(icmp) > 0 {
						alg.ICMP = parseICMP(icmp[0].(map[string]interface{}))
					}
				case "dns":
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
				case "ftp":
					if ftp, ok := algMap["ftp"].([]interface{}); ok && len(ftp) > 0 {
						alg.FTP = parseFTP(ftp[0].(map[string]interface{}))
					}
				case "sunrpc":
					if sunrpc, ok := algMap["sunrpc"].([]interface{}); ok && len(sunrpc) > 0 {
						alg.SunRPC = parseSunRPC(sunrpc)
					}
				case "msrpc":
					if msrpc, ok := algMap["msrpc"].([]interface{}); ok {
						alg.MSRPC = parseMSRPC(msrpc)
					}
				case "tftp":
					alg.TFTP = &TFTP{} // TFTP doesn't have any specific fields
				case "rtsp":
					alg.RTSP = &RTSP{} // RTSP doesn't have any specific fields
				}

				app.Spec.ALG = alg
			} else {
				app.Spec.ALG = nil
				app.Spec.Timeout = nil
			}
		}
	}

	jsonBytes, err := json.Marshal(app)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err = http.NewRequestWithContext(ctx, "PUT", config.Server+"/configs/security/v1/tenant/default/apps/"+d.Id(), bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Request method: %s", req.Method)
	log.Printf("[DEBUG] Request URL: %s", req.URL.String())
	log.Printf("[DEBUG] Request body: %s", jsonBytes)

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err = client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("failed to update app: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "App update failed",
				Detail:   errMsg,
			},
		}
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
