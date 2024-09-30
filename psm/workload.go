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

func resourceWorkload() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceWorkloadCreate,
		ReadContext:   resourceWorkloadRead,
		UpdateContext: resourceWorkloadUpdate,
		DeleteContext: resourceWorkloadDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceWorkloadImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"host_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"migration_timeout": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "60s",
			},
			"interface": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"mac_address": {
							Type:     schema.TypeString,
							Required: true,
						},
						"external_vlan": {
							Type:     schema.TypeInt,
							Required: true,
						},
						"ip_addresses": {
							Type:     schema.TypeList,
							Required: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"micro_seg_vlan": {
							Type:     schema.TypeInt,
							Optional: true,
						},
						"network": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"vni": {
							Type:     schema.TypeInt,
							Optional: true,
						},
					},
				},
			},
		},
	}
}

type Workload struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api-version"`
	Meta       struct {
		Name            string `json:"name"`
		Tenant          string `json:"tenant"`
		Namespace       string `json:"namespace"`
		GenerationID    string `json:"generation-id"`
		ResourceVersion string `json:"resource-version"`
		UUID            string `json:"uuid"`
		CreationTime    string `json:"creation-time"`
		ModTime         string `json:"mod-time"`
		SelfLink        string `json:"self-link"`
	} `json:"meta"`
	Spec struct {
		HostName         string `json:"host-name"`
		MigrationTimeout string `json:"migration-timeout"`
		Interfaces       []struct {
			MacAddress   string   `json:"mac-address"`
			MicroSegVlan *int     `json:"micro-seg-vlan,omitempty"`
			ExternalVlan int      `json:"external-vlan"`
			IPAddresses  []string `json:"ip-addresses"`
			Network      *string  `json:"network,omitempty"`
			Vni          *int     `json:"vni,omitempty"`
		} `json:"interfaces"`
	} `json:"spec"`
}

func resourceWorkloadCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	workload := &Workload{
		Kind:       "Workload",
		APIVersion: "v1",
	}
	workload.Meta.Name = d.Get("name").(string)
	workload.Meta.Namespace = "default"
	workload.Meta.Tenant = "default"
	workload.Spec.HostName = d.Get("host_name").(string)
	workload.Spec.MigrationTimeout = d.Get("migration_timeout").(string)

	interfaces := d.Get("interface").([]interface{})
	for _, iface := range interfaces {
		ifaceMap := iface.(map[string]interface{})
		workloadIface := struct {
			MacAddress   string   `json:"mac-address"`
			MicroSegVlan *int     `json:"micro-seg-vlan,omitempty"`
			ExternalVlan int      `json:"external-vlan"`
			IPAddresses  []string `json:"ip-addresses"`
			Network      *string  `json:"network,omitempty"`
			Vni          *int     `json:"vni,omitempty"`
		}{
			MacAddress:   ifaceMap["mac_address"].(string),
			ExternalVlan: ifaceMap["external_vlan"].(int),
			IPAddresses:  expandStringList(ifaceMap["ip_addresses"].([]interface{})),
		}
		if v, ok := ifaceMap["micro_seg_vlan"]; ok {
			microSegVlan := v.(int)
			workloadIface.MicroSegVlan = &microSegVlan
		}
		if v, ok := ifaceMap["network"]; ok {
			network := v.(string)
			workloadIface.Network = &network
		}
		if v, ok := ifaceMap["vni"]; ok {
			vni := v.(int)
			workloadIface.Vni = &vni
		}
		workload.Spec.Interfaces = append(workload.Spec.Interfaces, workloadIface)
	}

	jsonBytes, err := json.Marshal(workload)
	if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Workload create payload: %s", string(jsonBytes))

	req, err := http.NewRequestWithContext(ctx, "POST", config.Server+"/configs/workload/v1/tenant/default/workloads", bytes.NewBuffer(jsonBytes))
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
		bodyBytes, _ := io.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("failed to create workload: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		return diag.Errorf(errMsg)
	}

	responseBody := &Workload{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responseBody.Meta.Name)

	return resourceWorkloadRead(ctx, d, m)
}

func resourceWorkloadRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	name := d.Id()
	url := fmt.Sprintf("%s/configs/workload/v1/tenant/default/workloads/%s", config.Server, name)

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
		d.SetId("")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to read workload: HTTP %s", resp.Status)
	}

	workload := &Workload{}
	if err := json.NewDecoder(resp.Body).Decode(workload); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", workload.Meta.Name)
	d.Set("host_name", workload.Spec.HostName)
	d.Set("migration_timeout", workload.Spec.MigrationTimeout)

	interfaces := make([]interface{}, len(workload.Spec.Interfaces))
	for i, iface := range workload.Spec.Interfaces {
		ifaceMap := map[string]interface{}{
			"mac_address":   iface.MacAddress,
			"external_vlan": iface.ExternalVlan,
			"ip_addresses":  iface.IPAddresses,
		}
		if iface.MicroSegVlan != nil {
			ifaceMap["micro_seg_vlan"] = *iface.MicroSegVlan
		}
		if iface.Network != nil {
			ifaceMap["network"] = *iface.Network
		}
		if iface.Vni != nil {
			ifaceMap["vni"] = *iface.Vni
		}
		interfaces[i] = ifaceMap
	}
	d.Set("interface", interfaces)

	return nil
}

func resourceWorkloadUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := fmt.Sprintf("%s/configs/workload/v1/tenant/default/workloads/%s", config.Server, d.Get("name").(string))
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
		bodyBytes, _ := io.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("failed to read workload: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		return diag.Errorf(errMsg)
	}

	var currentWorkload Workload
	if err := json.NewDecoder(resp.Body).Decode(&currentWorkload); err != nil {
		return diag.FromErr(err)
	}

	workload := currentWorkload
	workload.Spec.HostName = d.Get("host_name").(string)
	workload.Spec.MigrationTimeout = d.Get("migration_timeout").(string)

	interfaces := d.Get("interface").([]interface{})
	workload.Spec.Interfaces = []struct {
		MacAddress   string   `json:"mac-address"`
		MicroSegVlan *int     `json:"micro-seg-vlan,omitempty"`
		ExternalVlan int      `json:"external-vlan"`
		IPAddresses  []string `json:"ip-addresses"`
		Network      *string  `json:"network,omitempty"`
		Vni          *int     `json:"vni,omitempty"`
	}{}
	for _, iface := range interfaces {
		ifaceMap := iface.(map[string]interface{})
		workloadIface := struct {
			MacAddress   string   `json:"mac-address"`
			MicroSegVlan *int     `json:"micro-seg-vlan,omitempty"`
			ExternalVlan int      `json:"external-vlan"`
			IPAddresses  []string `json:"ip-addresses"`
			Network      *string  `json:"network,omitempty"`
			Vni          *int     `json:"vni,omitempty"`
		}{
			MacAddress:   ifaceMap["mac_address"].(string),
			ExternalVlan: ifaceMap["external_vlan"].(int),
			IPAddresses:  expandStringList(ifaceMap["ip_addresses"].([]interface{})),
		}
		if v, ok := ifaceMap["micro_seg_vlan"]; ok {
			microSegVlan := v.(int)
			workloadIface.MicroSegVlan = &microSegVlan
		}
		if v, ok := ifaceMap["network"]; ok {
			network := v.(string)
			workloadIface.Network = &network
		}
		if v, ok := ifaceMap["vni"]; ok {
			vni := v.(int)
			workloadIface.Vni = &vni
		}
		workload.Spec.Interfaces = append(workload.Spec.Interfaces, workloadIface)
	}

	jsonBytes, err := json.Marshal(workload)
	if err != nil {
		return diag.FromErr(err)
	}

	log.Printf("[DEBUG] Workload update payload: %s", string(jsonBytes))

	req, err = http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err = client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("failed to update workload: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
		return diag.Errorf(errMsg)
	}

	return resourceWorkloadRead(ctx, d, m)
}

func resourceWorkloadDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := fmt.Sprintf("%s/configs/workload/v1/tenant/default/workloads/%s", config.Server, d.Get("name").(string))

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return diag.Errorf("failed to delete workload: HTTP %s", resp.Status)
	}

	d.SetId("")

	return nil
}

func resourceWorkloadImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	config := m.(*Config)

	name := d.Id()

	url := fmt.Sprintf("%s/configs/workload/v1/tenant/default/workloads/%s", config.Server, name)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request to import Workload: %v", err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	client := config.Client()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error importing Workload: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to import Workload: HTTP %s", resp.Status)
	}

	var workload Workload
	if err := json.NewDecoder(resp.Body).Decode(&workload); err != nil {
		return nil, fmt.Errorf("error decoding Workload response: %v", err)
	}

	d.SetId(workload.Meta.Name)
	d.Set("name", workload.Meta.Name)
	d.Set("host_name", workload.Spec.HostName)
	d.Set("migration_timeout", workload.Spec.MigrationTimeout)

	interfaces := make([]interface{}, len(workload.Spec.Interfaces))
	for i, iface := range workload.Spec.Interfaces {
		ifaceMap := map[string]interface{}{
			"mac_address":   iface.MacAddress,
			"external_vlan": iface.ExternalVlan,
			"ip_addresses":  iface.IPAddresses,
		}
		if iface.MicroSegVlan != nil {
			ifaceMap["micro_seg_vlan"] = *iface.MicroSegVlan
		}
		if iface.Network != nil {
			ifaceMap["network"] = *iface.Network
		}
		if iface.Vni != nil {
			ifaceMap["vni"] = *iface.Vni
		}
		interfaces[i] = ifaceMap
	}
	d.Set("interface", interfaces)

	return []*schema.ResourceData{d}, nil
}
