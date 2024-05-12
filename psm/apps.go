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
							Type:     schema.TypeString,
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
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"type": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"icmp": {
										Type:     schema.TypeList,
										Optional: true,
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
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"drop_multi_question_packets": {
													Type:     schema.TypeBool,
													Optional: true,
												},
												"drop_large_domain_name_packets": {
													Type:     schema.TypeBool,
													Optional: true,
												},
												"drop_long_label_packets": {
													Type:     schema.TypeBool,
													Optional: true,
												},
												"max_message_length": {
													Type:     schema.TypeInt,
													Optional: true,
													Default:  "512",
												},
												"timeout": {
													Type:     schema.TypeString,
													Optional: true,
													Default:  "60s",
												},
											},
										},
									},
									"ftp": {
										Type:     schema.TypeList,
										Optional: true,
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
										ForceNew: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"program_id": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"timeout": {
													Type:     schema.TypeInt,
													Optional: true,
													Default:  "60s",
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
													Optional: true,
												},
												"timeout": {
													Type:     schema.TypeInt,
													Optional: true,
													Default:  "60s",
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

type App struct {
	Kind       interface{} `json:"kind"`
	APIVersion interface{} `json:"api-version"`
	Meta       struct {
		Name            string      `json:"name"`
		Tenant          interface{} `json:"tenant"`
		Namespace       interface{} `json:"namespace"`
		GenerationID    interface{} `json:"generation-id"`
		ResourceVersion interface{} `json:"resource-version"`
		UUID            interface{} `json:"uuid"`
		Labels          interface{} `json:"labels"`
		SelfLink        interface{} `json:"self-link"`
		DisplayName     string      `json:"display-name"`
	} `json:"meta"`
	Spec struct {
		ProtoPorts []ProtoPorts `json:"proto-ports"`
		Apps       []string     `json:"apps"`
	} `json:"spec"`
}

type ProtoPorts struct {
	Protocol string `json:"protocol"`
	Ports    string `json:"ports"`
}

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
				} else {
					// `port["protocol"]` is not a string
				}

				if ports, ok := port["ports"].(string); ok {
					protoPort.Ports = ports
				} else {
					// `port["ports"]` is not a string

					// `port["ports"]` is not a []interface{}
				}
				app.Spec.ProtoPorts = append(app.Spec.ProtoPorts, protoPort)
			}
		}
		if apps, ok := specMap["apps"].([]interface{}); ok {
			for _, a := range apps {
				app.Spec.Apps = append(app.Spec.Apps, a.(string))
			}
		}

		// 	if meta, ok := d.GetOk("meta"); ok {
		// 		metaList := meta.([]interface{})
		// 		metaMap := metaList[0].(map[string]interface{})
		// 		app.Meta.Name = metaMap["name"].(string)
		// 	}
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
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
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

	// Get the UUID of the Apps resource
	//appUUID := d.Id()

	// Create a new HTTP GET request to fetch the Apps resource
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

	d.Set("meta", []interface{}{
		map[string]interface{}{
			"name":      app.Meta.Name,
			"tenant":    app.Meta.Tenant,
			"namespace": app.Meta.Namespace,
			"uuid":      app.Meta.Namespace,
		},
	})
	d.Set("display_name", app.Meta.DisplayName)
	d.Set("spec.apps", app.Spec.Apps)
	protoPorts := make([]map[string]interface{}, len(app.Spec.ProtoPorts))
	for i, pp := range app.Spec.ProtoPorts {
		protoPorts[i] = map[string]interface{}{
			"protocol": pp.Protocol,
			"ports":    pp.Ports,
		}
	}
	d.Set("spec.proto_ports", protoPorts)

	return nil
}

func resourceAppsUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	app := &App{}

	if d.HasChange("spec") || d.HasChange("meta") {
		if spec, ok := d.Get("spec").([]interface{}); ok && len(spec) > 0 {
			specMap := spec[0].(map[string]interface{})
			if protoPorts, ok := specMap["proto_ports"].([]interface{}); ok {
				app.Spec.ProtoPorts = []ProtoPorts{}
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
				app.Spec.Apps = []string{}
				for _, a := range apps {
					app.Spec.Apps = append(app.Spec.Apps, a.(string))
				}
			}
			app.Meta.DisplayName = d.Get("display_name").(string)
		}

		jsonBytes, err := json.Marshal(app)
		if err != nil {
			return diag.FromErr(err)
		}

		req, err := http.NewRequestWithContext(ctx, "PUT", config.Server+"/configs/security/v1/tenant/default/apps/"+d.Id(), bytes.NewBuffer(jsonBytes))
		if err != nil {
			return diag.FromErr(err)
		}

		log.Printf("[DEBUG] Request method: %s", req.Method)
		log.Printf("[DEBUG] Request URL: %s", req.URL.String())
		log.Printf("[DEBUG] Request body: %s", jsonBytes)

		req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

		resp, err := client.Do(req)
		if err != nil {
			return diag.FromErr(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := ioutil.ReadAll(resp.Body)
			errMsg := fmt.Sprintf("failed to update app: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
			return diag.Diagnostics{
				{
					Severity: diag.Error,
					Summary:  "App update failed",
					Detail:   errMsg,
				},
			}
		}
	}

	return append(diag.Diagnostics{}, resourceAppsRead(ctx, d, m)...)
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
