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

// Define the Terraform resource schema for ip_collections
func resourceIPCollection() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceIPCollectionCreate,
		ReadContext:   resourceIPCollectionRead,
		UpdateContext: resourceIPCollectionUpdate,
		DeleteContext: resourceIPCollectionDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceIPCollectionImport,
		},
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
				ForceNew: false,
			},
			"ip_collections": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				ForceNew: false,
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
		IPCollections []string `json:"ipcollections"`
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
	if ipcollections, ok := d.GetOk("ip_collections"); ok {
		for _, addr := range ipcollections.([]interface{}) {
			ipCollection.Spec.IPCollections = append(ipCollection.Spec.IPCollections, addr.(string))
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

	// Log the request details
	log.Printf("[DEBUG] Request method: %s", req.Method)
	log.Printf("[DEBUG] Request URL: %s", req.URL.String())
	log.Printf("[DEBUG] Request body: %s", jsonBytes)

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

	if resp.StatusCode == http.StatusNotFound {
		// If the resource doesn't exist, remove it from the state
		d.SetId("")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to read ip_collection: HTTP %s", resp.Status)
	}

	ipCollection := &IPCollection{}
	if err := json.NewDecoder(resp.Body).Decode(ipCollection); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", ipCollection.Meta.Name)
	d.Set("addresses", ipCollection.Spec.Addresses)
	d.Set("ipcollections", ipCollection.Spec.IPCollections)

	return nil
}

func resourceIPCollectionUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	ipCollection := &IPCollection{}
	ipCollection.Meta.Name = d.Get("name").(string)
	if d.HasChange("addresses") {
		ipCollection.Spec.Addresses = nil
		for _, addr := range d.Get("addresses").([]interface{}) {
			ipCollection.Spec.Addresses = append(ipCollection.Spec.Addresses, addr.(string))
		}
	}
	if d.HasChange("ip_collections") {
		ipCollection.Spec.IPCollections = nil
		for _, addr := range d.Get("ip_collections").([]interface{}) {
			ipCollection.Spec.IPCollections = append(ipCollection.Spec.IPCollections, addr.(string))
		}
	}

	jsonBytes, err := json.Marshal(ipCollection)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", config.Server+"/configs/network/v1/tenant/default/ipcollections/"+d.Id(), bytes.NewBuffer(jsonBytes))
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
		return diag.Errorf("failed to update ip_collection: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
	}

	// Log the request details
	log.Printf("[DEBUG] Request method: %s", req.Method)
	log.Printf("[DEBUG] Request URL: %s", req.URL.String())
	log.Printf("[DEBUG] Request body: %s", jsonBytes)

	return resourceIPCollectionRead(ctx, d, m)
}

// Implement the Delete method for ip_collections
func resourceIPCollectionDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	// Construct the URL for the ipCollection based on its name
	url := config.Server + "/configs/network/v1/tenant/default/ipcollections/" + d.Get("name").(string)

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
		return diag.Errorf("failed to delete ip_collection: HTTP %s", resp.Status)
	}

	// Clear the resource ID as it's been deleted from the PSM server.
	d.SetId("")

	return nil
}

func resourceIPCollectionImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	// The ID passed will be the name of the IP collection
	name := d.Id()

	// Set the name in the ResourceData
	d.Set("name", name)

	// Call Read to populate the rest of the data
	diags := resourceIPCollectionRead(ctx, d, m)
	if diags.HasError() {
		return nil, fmt.Errorf("failed to read imported IP collection: %v", diags)
	}

	return []*schema.ResourceData{d}, nil
}
