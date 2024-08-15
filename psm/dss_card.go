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

// Although we manage a Distributed Service Switch (DSS), a Distributed Service Module (DSM) is treated as a Distributed Servicesa Card (DSC) ;)
func resourceDistributedServiceCard() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceDistributedServiceCardCreate,
		ReadContext:   resourceDistributedServiceCardRead,
		UpdateContext: resourceDistributedServiceCardUpdate,
		DeleteContext: resourceDistributedServiceCardDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceDistributedServiceCardImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"labels": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"fwlog_policy_name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"flow_export_policy_name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"serial_num": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"primary_mac": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"dsc_version": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"dsc_sku": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ip_address": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"default_gw": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"dns_servers": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"is_connected_to_psm": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"host_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"dss_version": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"forwarding_profile": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"security_policy_rule_scale_profile": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"dsms": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"unit_id": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"mac_address": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

type DistributedServiceCard struct {
	Kind       string    `json:"kind"`
	APIVersion string    `json:"api-version"`
	Meta       DSCMeta   `json:"meta"`
	Spec       DSCSpec   `json:"spec"`
	Status     DSCStatus `json:"status,omitempty"`
}

type DSCMeta struct {
	Name            string            `json:"name"`
	GenerationID    string            `json:"generation-id,omitempty"`
	ResourceVersion string            `json:"resource-version,omitempty"`
	UUID            string            `json:"uuid,omitempty"`
	CreationTime    string            `json:"creation-time,omitempty"`
	ModTime         string            `json:"mod-time,omitempty"`
	SelfLink        string            `json:"self-link,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
}

type DSCSpec struct {
	Admit            bool        `json:"admit"`
	ID               string      `json:"id"`
	IPConfig         IPConfig    `json:"ip-config"`
	MgmtMode         string      `json:"mgmt-mode"`
	NetworkMode      string      `json:"network-mode"`
	Controllers      []string    `json:"controllers"`
	DSCProfile       string      `json:"dscprofile"`
	FwlogPolicy      DSCPolicy   `json:"fwlog-policy,omitempty"`
	EnableSecureBoot bool        `json:"enable-secure-boot"`
	FlowExportPolicy []DSCPolicy `json:"flow-export-policy,omitempty"`
}

type IPConfig struct {
	IPAddress  string   `json:"ip-address"`
	DefaultGW  string   `json:"default-gw"`
	DNSServers []string `json:"dns-servers"`
}

type DSCPolicy struct {
	Tenant string `json:"tenant"`
	Name   string `json:"name"`
}

type DSCStatus struct {
	AdmissionPhase                 string             `json:"admission-phase"`
	Conditions                     []DSCCondition     `json:"conditions"`
	SerialNum                      string             `json:"serial-num"`
	PrimaryMAC                     string             `json:"primary-mac"`
	IPConfig                       IPConfig           `json:"ip-config"`
	SystemInfo                     SystemInfo         `json:"system-info"`
	DSCVersion                     string             `json:"DSCVersion"`
	DSCSku                         string             `json:"DSCSku"`
	ControlPlaneStatus             ControlPlaneStatus `json:"control-plane-status"`
	IsConnectedToPSM               bool               `json:"is-connected-to-psm"`
	NumMACAddress                  int                `json:"num-mac-address"`
	SecureBooted                   bool               `json:"secure-booted"`
	AlomPresent                    bool               `json:"alom-present"`
	PackageType                    string             `json:"package-type"`
	DSSInfo                        DSSInfo            `json:"dss-info"`
	SecurityPolicyRuleScaleProfile string             `json:"security-policy-rule-scale-profile"`
}

type DSCCondition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	LastTransitionTime string `json:"last-transition-time"`
	Reason             string `json:"reason,omitempty"`
}

type SystemInfo struct {
	OSInfo     OSInfo     `json:"os-info"`
	MemoryInfo MemoryInfo `json:"memory-info"`
}

type OSInfo struct {
	Type          string `json:"type"`
	KernelRelease string `json:"kernel-release"`
	Processor     string `json:"processor"`
}

type MemoryInfo struct {
	Type string `json:"type"`
}

type ControlPlaneStatus struct {
	LastUpdatedTime string `json:"last-updated-time"`
}

type DSSInfo struct {
	HostName          string `json:"host-name"`
	Version           string `json:"version"`
	DSMs              []DSM  `json:"dsms"`
	ForwardingProfile string `json:"forwarding-profile"`
}

type DSM struct {
	UnitID     int    `json:"unit-id"`
	MACAddress string `json:"mac-address"`
}

func resourceDistributedServiceCardCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)

	name := d.Get("name").(string)
	fwlogPolicyName := d.Get("fwlog_policy_name").(string)
	flowExportPolicyName := d.Get("flow_export_policy_name").(string)
	labels := d.Get("labels").(map[string]interface{})

	dsc := &DistributedServiceCard{
		Kind:       "DistributedServiceCard",
		APIVersion: "v1",
		Meta: DSCMeta{
			Name:   name,
			Labels: make(map[string]string),
		},
		Spec: DSCSpec{
			FwlogPolicy: DSCPolicy{
				Tenant: "default",
				Name:   fwlogPolicyName,
			},
			FlowExportPolicy: []DSCPolicy{
				{
					Tenant: "default",
					Name:   flowExportPolicyName,
				},
			},
		},
	}

	for k, v := range labels {
		dsc.Meta.Labels[k] = v.(string)
	}

	// Call API to create the resource
	err := createDistributedServiceCard(ctx, config, dsc)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(name)

	return resourceDistributedServiceCardRead(ctx, d, m)
}

func resourceDistributedServiceCardRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	name := d.Id()

	dsc, err := getDistributedServiceCard(ctx, config, name)
	if err != nil {
		return diag.FromErr(err)
	}

	if dsc == nil {
		d.SetId("")
		return nil
	}

	d.Set("name", dsc.Meta.Name)
	d.Set("labels", dsc.Meta.Labels)
	d.Set("fwlog_policy_name", dsc.Spec.FwlogPolicy.Name)
	if len(dsc.Spec.FlowExportPolicy) > 0 {
		d.Set("flow_export_policy_name", dsc.Spec.FlowExportPolicy[0].Name)
	}

	// Set read-only fields
	d.Set("serial_num", dsc.Status.SerialNum)
	d.Set("primary_mac", dsc.Status.PrimaryMAC)
	d.Set("dsc_version", dsc.Status.DSCVersion)
	d.Set("dsc_sku", dsc.Status.DSCSku)
	d.Set("ip_address", dsc.Spec.IPConfig.IPAddress)
	d.Set("default_gw", dsc.Spec.IPConfig.DefaultGW)
	d.Set("dns_servers", dsc.Spec.IPConfig.DNSServers)
	d.Set("is_connected_to_psm", dsc.Status.IsConnectedToPSM)
	d.Set("host_name", dsc.Status.DSSInfo.HostName)
	d.Set("dss_version", dsc.Status.DSSInfo.Version)
	d.Set("forwarding_profile", dsc.Status.DSSInfo.ForwardingProfile)
	d.Set("security_policy_rule_scale_profile", dsc.Status.SecurityPolicyRuleScaleProfile)

	dsms := make([]map[string]interface{}, len(dsc.Status.DSSInfo.DSMs))
	for i, dsm := range dsc.Status.DSSInfo.DSMs {
		dsms[i] = map[string]interface{}{
			"unit_id":     dsm.UnitID,
			"mac_address": dsm.MACAddress,
		}
	}
	d.Set("dsms", dsms)

	return nil
}

func resourceDistributedServiceCardUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	name := d.Id()

	// Fetch the current state of the DSC
	currentDSC, err := getDistributedServiceCard(ctx, config, name)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error fetching current DSC state: %s", err))
	}

	// Create update request based on the current state
	updateRequest := DistributedServiceCard{
		Kind:       "DistributedServiceCard",
		APIVersion: "v1",
		Meta:       currentDSC.Meta,
		Spec:       currentDSC.Spec,
	}

	// Update only the fields that have changed
	if d.HasChange("ip_address") || d.HasChange("default_gw") || d.HasChange("dns_servers") {
		if d.HasChange("ip_address") {
			updateRequest.Spec.IPConfig.IPAddress = d.Get("ip_address").(string)
		}
		if d.HasChange("default_gw") {
			updateRequest.Spec.IPConfig.DefaultGW = d.Get("default_gw").(string)
		}
		if d.HasChange("dns_servers") {
			dnsServers := d.Get("dns_servers").([]interface{})
			updateRequest.Spec.IPConfig.DNSServers = make([]string, len(dnsServers))
			for i, v := range dnsServers {
				updateRequest.Spec.IPConfig.DNSServers[i] = v.(string)
			}
		}
	}

	if d.HasChange("fwlog_policy_name") {
		updateRequest.Spec.FwlogPolicy = DSCPolicy{
			Tenant: "default",
			Name:   d.Get("fwlog_policy_name").(string),
		}
	}

	if d.HasChange("flow_export_policy_name") {
		updateRequest.Spec.FlowExportPolicy = []DSCPolicy{{
			Tenant: "default",
			Name:   d.Get("flow_export_policy_name").(string),
		}}
	}

	if d.HasChange("labels") {
		labels := d.Get("labels").(map[string]interface{})
		updateRequest.Meta.Labels = make(map[string]string)
		for k, v := range labels {
			updateRequest.Meta.Labels[k] = v.(string)
		}
	}

	// Convert the update request to JSON
	jsonData, err := json.Marshal(updateRequest)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error marshaling update request: %s", err))
	}

	// Log the update request for debugging
	log.Printf("[DEBUG] Update request: %s", string(jsonData))

	// Prepare the HTTP request
	url := fmt.Sprintf("%s/configs/cluster/v1/distributedservicecards/%s", config.Server, name)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating request: %s", err))
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	// Send the request
	client := config.Client()
	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error sending request: %s", err))
	}
	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return diag.FromErr(fmt.Errorf("API request failed with status code: %d, body: %s, URL: %s", resp.StatusCode, string(bodyBytes), url))
	}

	// Log the successful update
	log.Printf("[INFO] Successfully updated DistributedServiceCard: %s", name)

	// Refresh the state with the latest data
	return resourceDistributedServiceCardRead(ctx, d, m)
}

func resourceDistributedServiceCardDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	name := d.Id()

	// Clear labels
	err := updateDistributedServiceCardLabels(ctx, config, name, make(map[string]string))
	if err != nil {
		return diag.FromErr(err)
	}

	// Remove the resource from Terraform state
	d.SetId("")

	return diag.Diagnostics{
		diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "DistributedServiceCard partially deleted",
			Detail:   "Labels have been cleared. The resource itself cannot be fully deleted from the system.",
		},
	}
}

func createDistributedServiceCard(ctx context.Context, config *Config, dsc *DistributedServiceCard) error {
	client := config.Client()

	// Construct the API URL
	url := fmt.Sprintf("%s/configs/cluster/v1/distributedservicecards", config.Server)

	// Marshal the DSC to JSON
	jsonData, err := json.Marshal(dsc)
	if err != nil {
		return fmt.Errorf("error marshaling DSC: %s", err)
	}

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error creating request: %s", err)
	}

	// Add necessary headers
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %s", err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
	}

	return nil
}

func resourceDistributedServiceCardImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	config := m.(*Config)

	name := d.Id()

	dsc, err := getDistributedServiceCard(ctx, config, name)
	if err != nil {
		return nil, fmt.Errorf("error fetching DistributedServiceCard with name %s: %s", name, err)
	}

	if dsc == nil {
		return nil, fmt.Errorf("no DistributedServiceCard found with name %s", name)
	}

	d.Set("name", dsc.Meta.Name)
	if dsc.Spec.FwlogPolicy.Name != "" {
		d.Set("fwlog_policy_name", dsc.Spec.FwlogPolicy.Name)
	}
	if len(dsc.Spec.FlowExportPolicy) > 0 && dsc.Spec.FlowExportPolicy[0].Name != "" {
		d.Set("flow_export_policy_name", dsc.Spec.FlowExportPolicy[0].Name)
	}
	if len(dsc.Meta.Labels) > 0 {
		d.Set("labels", dsc.Meta.Labels)
	}

	// Set read-only fields
	d.Set("serial_num", dsc.Status.SerialNum)
	d.Set("primary_mac", dsc.Status.PrimaryMAC)
	d.Set("dsc_version", dsc.Status.DSCVersion)
	d.Set("dsc_sku", dsc.Status.DSCSku)

	return []*schema.ResourceData{d}, nil
}

func getDistributedServiceCard(ctx context.Context, config *Config, name string) (*DistributedServiceCard, error) {
	url := fmt.Sprintf("%s/configs/cluster/v1/distributedservicecards/%s", config.Server, name)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %s", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	client := config.Client()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
	}

	var dsc DistributedServiceCard
	err = json.NewDecoder(resp.Body).Decode(&dsc)
	if err != nil {
		return nil, fmt.Errorf("error decoding response: %s", err)
	}

	return &dsc, nil
}

func updateDistributedServiceCardLabels(ctx context.Context, config *Config, name string, labels map[string]string) error {
	client := config.Client()

	url := fmt.Sprintf("%s/configs/cluster/v1/distributedservicecards/%s", config.Server, name)

	payload := struct {
		Meta struct {
			Labels map[string]string `json:"labels"`
		} `json:"meta"`
	}{
		Meta: struct {
			Labels map[string]string `json:"labels"`
		}{
			Labels: labels,
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshaling labels: %s", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error creating request: %s", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed with status code: %d, body: %s, URL: %s", resp.StatusCode, string(bodyBytes), url)
	}

	return nil
}
