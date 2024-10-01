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

func resourceHosts() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceHostsCreate,
		ReadContext:   resourceHostsRead,
		UpdateContext: resourceHostsUpdate,
		DeleteContext: resourceHostsDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceHostsImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"host_type": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"dscs": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"mac_address": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
				Set: dscHash,
			},
			"pnic_info": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"mac_address": {
							Type:     schema.TypeString,
							Required: true,
						},
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
				Set: pnicHash,
			},
			"uuid": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

type HostConfig struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api-version"`
	Meta       struct {
		Name            string      `json:"name"`
		Tenant          interface{} `json:"tenant,omitempty"`
		Namespace       interface{} `json:"namespace,omitempty"`
		GenerationID    string      `json:"generation-id,omitempty"`
		ResourceVersion string      `json:"resource-version,omitempty"`
		UUID            string      `json:"uuid,omitempty"`
		Labels          interface{} `json:"labels,omitempty"`
		SelfLink        string      `json:"self-link,omitempty"`
		DisplayName     interface{} `json:"display-name,omitempty"`
	} `json:"meta"`
	Spec struct {
		DSCs     []DSC  `json:"dscs,omitempty"`
		PNICInfo []PNIC `json:"pnic-info,omitempty"`
		HostType string `json:"hostType,omitempty"`
	} `json:"spec"`
}

type PNIC struct {
	MacAddress string `json:"mac-address"`
	Name       string `json:"name"`
}

type DSC struct {
	ID         string `json:"id,omitempty"`
	MacAddress string `json:"mac-address,omitempty"`
}

func resourceHostsCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	host := &HostConfig{
		Kind:       "Host",
		APIVersion: "v1",
	}
	host.Meta.Name = d.Get("name").(string)
	host.Spec.HostType = determineHostType(d)
	d.Set("host_type", host.Spec.HostType)

	if v, ok := d.GetOk("dscs"); ok {
		dscsSet := v.(*schema.Set)
		host.Spec.DSCs = make([]DSC, 0, dscsSet.Len())
		for _, dsc := range dscsSet.List() {
			dscMap := dsc.(map[string]interface{})
			newDSC := DSC{}
			if id, ok := dscMap["id"].(string); ok && id != "" {
				newDSC.ID = id
			}
			if macAddress, ok := dscMap["mac_address"].(string); ok && macAddress != "" {
				newDSC.MacAddress = macAddress
			}
			if (newDSC.ID != "" && newDSC.MacAddress == "") || (newDSC.ID == "" && newDSC.MacAddress != "") {
				host.Spec.DSCs = append(host.Spec.DSCs, newDSC)
			}
		}
	}

	if v, ok := d.GetOk("pnic_info"); ok {
		pnicSet := v.(*schema.Set)
		host.Spec.PNICInfo = make([]PNIC, 0, pnicSet.Len())
		for _, pnic := range pnicSet.List() {
			pnicMap := pnic.(map[string]interface{})
			newPNIC := PNIC{
				MacAddress: pnicMap["mac_address"].(string),
				Name:       pnicMap["name"].(string),
			}
			host.Spec.PNICInfo = append(host.Spec.PNICInfo, newPNIC)
		}
	}

	jsonData, err := json.Marshal(host)
	if err != nil {
		return diag.FromErr(err)
	}

	url := fmt.Sprintf("%s/configs/cluster/v1/hosts", config.Server)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
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
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return diag.Errorf("failed to read error response body: %v", err)
		}
		return diag.Errorf("failed to create Host: HTTP %s, Body: %s", resp.Status, string(bodyBytes))
	}

	var createdHost HostConfig
	if err := json.NewDecoder(resp.Body).Decode(&createdHost); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdHost.Meta.Name)
	d.Set("uuid", createdHost.Meta.UUID)
	d.Set("host_type", d.Get("host_type").(string))

	return resourceHostsRead(ctx, d, m)
}

func resourceHostsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	name := d.Id()
	url := fmt.Sprintf("%s/configs/cluster/v1/hosts/%s", config.Server, name)

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
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return diag.Errorf("failed to read error response body: %v", err)
		}
		return diag.Errorf("failed to read Host Config: HTTP %s, Body: %s", resp.Status, string(bodyBytes))
	}

	hostConfig := &HostConfig{}
	if err := json.NewDecoder(resp.Body).Decode(hostConfig); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", hostConfig.Meta.Name)
	d.Set("uuid", hostConfig.Meta.UUID)

	dscs := schema.NewSet(dscHash, []interface{}{})
	for _, dsc := range hostConfig.Spec.DSCs {
		dscMap := make(map[string]interface{})
		if dsc.MacAddress != "" {
			dscMap["mac_address"] = dsc.MacAddress
		}
		if dsc.ID != "" {
			dscMap["id"] = dsc.ID
		}
		if len(dscMap) > 0 {
			dscs.Add(dscMap)
		}
	}
	d.Set("dscs", dscs)

	pnicInfo := schema.NewSet(pnicHash, []interface{}{})
	for _, pnic := range hostConfig.Spec.PNICInfo {
		pnicMap := map[string]interface{}{
			"mac_address": pnic.MacAddress,
			"name":        pnic.Name,
		}
		pnicInfo.Add(pnicMap)
	}
	d.Set("pnic_info", pnicInfo)

	hostType := determineHostType(d)
	d.Set("host_type", hostType)

	return nil
}

func resourceHostsUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	host := &HostConfig{
		Kind:       "Host",
		APIVersion: "v1",
	}
	host.Meta.Name = d.Get("name").(string)
	host.Meta.UUID = d.Get("uuid").(string)
	host.Spec.HostType = determineHostType(d)
	d.Set("host_type", host.Spec.HostType)

	if d.HasChange("dscs") {
		dscsSet := d.Get("dscs").(*schema.Set)
		host.Spec.DSCs = make([]DSC, 0, dscsSet.Len())
		for _, dsc := range dscsSet.List() {
			dscMap := dsc.(map[string]interface{})
			newDSC := DSC{}
			if id, ok := dscMap["id"].(string); ok && id != "" {
				newDSC.ID = id
			}
			if macAddress, ok := dscMap["mac_address"].(string); ok && macAddress != "" {
				newDSC.MacAddress = macAddress
			}
			host.Spec.DSCs = append(host.Spec.DSCs, newDSC)
		}
	}

	if d.HasChange("pnic_info") {
		pnicSet := d.Get("pnic_info").(*schema.Set)
		host.Spec.PNICInfo = make([]PNIC, 0, pnicSet.Len())
		for _, pnic := range pnicSet.List() {
			pnicMap := pnic.(map[string]interface{})
			newPNIC := PNIC{
				MacAddress: pnicMap["mac_address"].(string),
				Name:       pnicMap["name"].(string),
			}
			host.Spec.PNICInfo = append(host.Spec.PNICInfo, newPNIC)
		}
	}

	jsonData, err := json.Marshal(host)
	if err != nil {
		return diag.FromErr(err)
	}

	url := fmt.Sprintf("%s/configs/cluster/v1/hosts/%s", config.Server, d.Id())
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonData))
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
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return diag.Errorf("failed to read error response body: %v", err)
		}
		return diag.Errorf("failed to update Host: HTTP %s, Body: %s", resp.Status, string(bodyBytes))
	}

	return resourceHostsRead(ctx, d, m)
}

func resourceHostsDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	name := d.Get("name").(string)
	uuid := d.Get("uuid").(string)

	url := fmt.Sprintf("%s/configs/cluster/v1/hosts/%s", config.Server, name)
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

	if resp.StatusCode == http.StatusNotFound && uuid != "" {
		url = fmt.Sprintf("%s/configs/cluster/v1/hosts/%s", config.Server, uuid)
		req, err = http.NewRequestWithContext(ctx, "DELETE", url, nil)
		if err != nil {
			return diag.FromErr(err)
		}

		req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

		resp, err = client.Do(req)
		if err != nil {
			return diag.FromErr(err)
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return diag.Errorf("failed to read error response body: %v", err)
		}
		return diag.Errorf("failed to delete Host: HTTP %s, Body: %s", resp.Status, string(bodyBytes))
	}

	d.SetId("")
	return nil
}

func resourceHostsImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	config := m.(*Config)
	client := config.Client()

	name := d.Id()
	url := fmt.Sprintf("%s/configs/cluster/v1/hosts/%s", config.Server, name)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request to import Host Config: %v", err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error importing Host Config: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to import Host Config: HTTP %s", resp.Status)
	}

	var hostConfig HostConfig
	if err := json.NewDecoder(resp.Body).Decode(&hostConfig); err != nil {
		return nil, fmt.Errorf("error decoding Host Config response: %v", err)
	}

	d.SetId(hostConfig.Meta.Name)
	d.Set("name", hostConfig.Meta.Name)
	d.Set("host_type", hostConfig.Spec.HostType)

	dscs := make([]interface{}, len(hostConfig.Spec.DSCs))
	for i, dsc := range hostConfig.Spec.DSCs {
		dscMap := map[string]interface{}{
			"id":          dsc.ID,
			"mac_address": dsc.MacAddress,
		}
		dscs[i] = dscMap
	}
	d.Set("dscs", dscs)

	return []*schema.ResourceData{d}, nil
}
