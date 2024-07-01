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

func resourceVRF() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceVRFCreate,
		ReadContext:   resourceVRFRead,
		DeleteContext: resourceVRFDelete,
		UpdateContext: resourceVRFUpdate,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"ingress_security_policy": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: false,
			},
			"egress_security_policy": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: false,
			},
			"connection_tracking_mode": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: false,
			},
			"allow_session_reuse": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: false,
			},
		},
	}
}

type VRF struct {
	Kind       interface{} `json:"kind"`
	APIVersion interface{} `json:"api-version"`
	Meta       struct {
		Name            string      `json:"name"`
		Tenant          string      `json:"tenant"`
		Namespace       interface{} `json:"namespace"`
		GenerationID    interface{} `json:"generation-id"`
		ResourceVersion interface{} `json:"resource-version"`
		UUID            interface{} `json:"uuid"`
		Labels          interface{} `json:"labels"`
		SelfLink        interface{} `json:"self-link"`
		DisplayName     interface{} `json:"display-name"`
	} `json:"meta"`
	Spec struct {
		Type                                                  string        `json:"type"`
		RouterMacAddress                                      interface{}   `json:"router-mac-address"`
		VxlanVni                                              interface{}   `json:"vxlan-vni"`
		DefaultIpamPolicy                                     interface{}   `json:"default-ipam-policy"`
		IngressSecurityPolicy                                 []interface{} `json:"ingress-security-policy"`
		EgressSecurityPolicy                                  []interface{} `json:"egress-security-policy"`
		MaximumCpsPerNetworkPerDistributedServicesEntity      int           `json:"maximum-cps-per-network-per-distributed-services-entity"`
		MaximumSessionsPerNetworkPerDistributedServicesEntity int           `json:"maximum-sessions-per-network-per-distributed-services-entity"`
		FlowExportPolicy                                      []interface{} `json:"flow-export-policy"`
		IngressNatPolicy                                      []interface{} `json:"ingress-nat-policy"`
		EgressNatPolicy                                       []interface{} `json:"egress-nat-policy"`
		IpsecPolicy                                           []interface{} `json:"ipsec-policy"`
		SelectCPS                                             int           `json:"selectCPS"`
		SelectSessions                                        int           `json:"selectSessions"`
		ConnectionTracking                                    string        `json:"connection-tracking-mode"`
		AllowSessionReuse                                     string        `json:"allow-session-reuse"`
	} `json:"spec"`
}

func resourceVRFCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	vrf := &VRF{}
	vrf.Meta.Name = d.Get("name").(string)
	vrf.Meta.Tenant = "default"
	vrf.Spec.Type = "unknown"
	vrf.Spec.ConnectionTracking = d.Get("connection_tracking_mode").(string)
	vrf.Spec.AllowSessionReuse = d.Get("allow_session_reuse").(string)
	vrfName := d.Get("name").(string)
	if v, ok := d.GetOk("ingress_security_policy"); ok {
		vrf.Spec.IngressSecurityPolicy = []interface{}{v.(string)}
	}
	if v, ok := d.GetOk("egress_security_policy"); ok {
		vrf.Spec.EgressSecurityPolicy = []interface{}{v.(string)}
	}
	if vrfName == "default" {
		d.SetId("default")
		return nil
	}

	jsonBytes, err := json.Marshal(vrf)
	if err != nil {
		log.Printf("[ERROR] Error marshalling VRF: %s", err)
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Creating VRF with name: %s", vrf.Meta.Name)

	req, err := http.NewRequestWithContext(ctx, "POST", config.Server+"/configs/network/v1/tenant/default/virtualrouters", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when creating VRF: %s", err)
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("failed to create VRF: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "VRF creation failed",
				Detail:   errMsg,
			},
		}
	}

	responseBody := &VRF{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responseBody.Meta.UUID.(string))

	log.Printf("[DEBUG] VRF created with UUID: %s", responseBody.Meta.UUID.(string))

	return append(diag.Diagnostics{}, resourceVRFRead(ctx, d, m)...)
}

func resourceVRFRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/network/v1/tenant/default/virtualrouters/" + d.Get("name").(string)
	log.Printf("[DEBUG] Reading VRF with name: %s", d.Get("name").(string))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when reading VRF: %s", err)
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to read VRF: HTTP %s", resp.Status)
	}

	vrf := &VRF{}
	if err := json.NewDecoder(resp.Body).Decode(vrf); err != nil {
		return diag.FromErr(err)
	}

	// Set the properties from the response, need to confirm what we need to add or apply here....
	d.Set("name", vrf.Meta.Name)
	d.Set("kind", vrf.Kind)
	d.Set("api_version", vrf.APIVersion)

	return nil
}

func resourceVRFDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()
	vrfName := d.Get("name").(string)

	if vrfName == "default" {
		d.SetId("default")
		return nil
	}

	url := config.Server + "/configs/network/v1/tenant/default/virtualrouters/" + d.Get("name").(string)

	log.Printf("[DEBUG] Deleting VRF with name: %s", d.Get("name").(string))

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when deleting VRF: %s", err)
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to delete VRF: HTTP %s", resp.Status)
	}

	d.SetId("")

	return nil
}

func resourceVRFUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	vrf := &VRF{}
	vrf.Meta.Name = d.Get("name").(string)
	vrf.Meta.Tenant = "default"
	vrf.Spec.Type = "unknown"
	vrf.Spec.ConnectionTracking = d.Get("connection_tracking_mode").(string)
	vrf.Spec.AllowSessionReuse = d.Get("allow_session_reuse").(string)
	vrfName := d.Get("name").(string)
	if v, ok := d.GetOk("ingress_security_policy"); ok {
		vrf.Spec.IngressSecurityPolicy = []interface{}{v.(string)}
	}
	if v, ok := d.GetOk("egress_security_policy"); ok {
		vrf.Spec.EgressSecurityPolicy = []interface{}{v.(string)}
	}
	if vrfName == "default" {
		d.SetId("default")
		return nil
	}

	jsonBytes, err := json.Marshal(vrf)
	if err != nil {
		log.Printf("[ERROR] Error marshalling VRF: %s", err)
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Updating VRF with name: %s", vrf.Meta.Name)

	req, err := http.NewRequestWithContext(ctx, "PUT", config.Server+"/configs/network/v1/tenant/default/virtualrouters/"+vrf.Meta.Name, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when updating VRF: %s", err)
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("failed to update VRF: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "VRF update failed",
				Detail:   errMsg,
			},
		}
	}

	responseBody := &VRF{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responseBody.Meta.UUID.(string))

	log.Printf("[DEBUG] VRF updated with UUID: %s", responseBody.Meta.UUID.(string))

	return append(diag.Diagnostics{}, resourceVRFRead(ctx, d, m)...)
}
