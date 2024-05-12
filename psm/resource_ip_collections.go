package psm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Define the Terraform resource schema for ip_collections
func resourceIPCollection() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceIPCollectionCreate,
		ReadContext:   resourceIPCollectionRead,
		DeleteContext: resourceIPCollectionDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"addresses": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				ForceNew: true,
			},
			"ipcollections": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				ForceNew: true,
			},
		},
	}
}

// Define the data model for ip_collections
type IPCollection struct {
	Kind       interface{} `json:"kind"`
	APIVersion interface{} `json:"api-version"`
	Meta       struct {
		Name   string `json:"name"`
		Tenant string `json:"tenant"`
	} `json:"meta"`
	Spec struct {
		Addresses     []string `json:"addresses"`
		Ipcollections []string `json:"ipcollections"`
	} `json:"spec"`
}

// Implement the Create method for ip_collections
func resourceIPCollectionCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	ipCollection := &IPCollection{}
	ipCollection.Meta.Name = d.Get("name").(string)

	if addresses, ok := d.GetOk("addresses"); ok {
		for _, addr := range addresses.([]interface{}) {
			ipCollection.Spec.Addresses = append(ipCollection.Spec.Addresses, addr.(string))
		}
	}
	if ipcollections, ok := d.GetOk("ipcollections"); ok {
		for _, addr := range ipcollections.([]interface{}) {
			ipCollection.Spec.Ipcollections = append(ipCollection.Spec.Ipcollections, addr.(string))
		}
	}

	jsonBytes, err := json.Marshal(ipCollection)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", config.Server+"/configs/network/v1/tenant/default/ipcollections", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to create ip_collection: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
	}

	responseIPCollection := &IPCollection{}
	if err := json.NewDecoder(bytes.NewBuffer(bodyBytes)).Decode(responseIPCollection); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responseIPCollection.Meta.Name)

	return resourceIPCollectionRead(ctx, d, m)
}

func resourceIPCollectionUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	ipCollection := &IPCollection{}
	ipCollection.Meta.Name = d.Get("name").(string)
	if addresses, ok := d.GetOk("addresses"); ok {
		for _, addr := range addresses.([]interface{}) {
			ipCollection.Spec.Addresses = append(ipCollection.Spec.Addresses, addr.(string))
		}
	}
	if ipcollections, ok := d.GetOk("ipcollections"); ok {
		for _, addr := range ipcollections.([]interface{}) {
			ipCollection.Spec.Ipcollections = append(ipCollection.Spec.Ipcollections, addr.(string))
		}
	}

	jsonBytes, err := json.Marshal(ipCollection)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", config.Server+"/configs/network/v1/tenant/default/ipcollections/"+d.Get("name").(string), bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to create ip_collection: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
	}

	responseIPCollection := &IPCollection{}
	if err := json.NewDecoder(bytes.NewBuffer(bodyBytes)).Decode(responseIPCollection); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responseIPCollection.Meta.Name)

	return resourceIPCollectionRead(ctx, d, m)
}

// Implement the Read method for ip_collections
func resourceIPCollectionRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/network/v1/tenant/default/ipcollections/" + d.Get("name").(string)

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
		return diag.Errorf("failed to read ip_collection: HTTP %s", resp.Status)
	}

	ipCollection := &IPCollection{}
	if err := json.NewDecoder(resp.Body).Decode(ipCollection); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", ipCollection.Meta.Name)
	d.Set("addresses", ipCollection.Spec.Addresses)
	d.Set("ipcollections", ipCollection.Spec.Ipcollections)

	return nil
}

// Implement the Delete method for ip_collections
func resourceIPCollectionDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/network/v1/tenant/default/ipcollections/" + d.Get("name").(string)

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
		return diag.Errorf("failed to delete ip_collection: HTTP %s", resp.Status)
	}

	d.SetId("")

	return nil
}
