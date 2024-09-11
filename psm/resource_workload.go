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

func resourceWorkload() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceWorkloadCreate,
		ReadContext:   resourceWorkloadRead,
		DeleteContext: resourceWorkloadDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"ip_address": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "default",
				ForceNew: true,
			},
			"vlan_id": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  0,
				ForceNew: true,
			},
		},
	}
}

type Workload struct {
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
		DisplayName     interface{} `json:"display-name"`
	} `json:"meta"`
	Spec struct {
		HostName   interface{} `json:"host-name"`
		Interfaces []struct {
			MacAddress   interface{} `json:"mac-address"`
			MicroSegVlan interface{} `json:"micro-seg-vlan"`
			ExternalVlan int         `json:"external-vlan"`
			IPAddresses  []string    `json:"ip-addresses"`
			Network      interface{} `json:"network"`
			Vni          interface{} `json:"vni"`
		} `json:"interfaces"`
		MigrationTimeout string `json:"migration-timeout"`
	} `json:"spec"`
}

func resourceWorkloadCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	// Create a new workload instance and populate required fields
	workload := &Workload{}
	workload.Meta.Name = d.Get("name").(string)
	iface := struct {
		MacAddress   interface{} `json:"mac-address"`
		MicroSegVlan interface{} `json:"micro-seg-vlan"`
		ExternalVlan int         `json:"external-vlan"`
		IPAddresses  []string    `json:"ip-addresses"`
		Network      interface{} `json:"network"`
		Vni          interface{} `json:"vni"`
	}{
		IPAddresses:  []string{d.Get("ip_address").(string)},
		ExternalVlan: d.Get("vlan_id").(int),
	}
	workload.Spec.Interfaces = append(workload.Spec.Interfaces, iface)

	jsonBytes, err := json.Marshal(workload)
	if err != nil {
		return diag.FromErr(err)
	}

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
		return diag.Diagnostics{
			{
				Severity: diag.Error,
				Summary:  "Workload creation failed",
				Detail:   errMsg,
			},
		}
	}

	responseBody := &Workload{}
	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responseBody.Meta.UUID.(string))

	return append(diag.Diagnostics{}, resourceWorkloadRead(ctx, d, m)...)
}

func resourceWorkloadRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/workload/v1/tenant/default/workloads/" + d.Get("name").(string)

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
		return diag.Errorf("failed to read workload: HTTP %s", resp.Status)
	}

	workload := &Workload{}
	if err := json.NewDecoder(resp.Body).Decode(workload); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", workload.Meta.Name)
	if len(workload.Spec.Interfaces) > 0 {
		d.Set("ip_address", workload.Spec.Interfaces[0].IPAddresses[0])
		d.Set("vlan_id", workload.Spec.Interfaces[0].ExternalVlan)
	}

	return nil
}

func resourceWorkloadDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/workload/v1/tenant/default/workloads/" + d.Get("name").(string)

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
