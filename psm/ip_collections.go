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

// Define the Terraform resource schema for ip_collections
func resourceIPCollection() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceIPCollectionCreate,
		ReadContext:   resourceIPCollectionRead,
		UpdateContext: resourceIPCollectionUpdate,
		DeleteContext: resourceIPCollectionDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"display_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"tenant": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "default",
			},
			"addresses": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"ip_collections": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"address_family": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "IPv4",
				ValidateFunc: validation.StringInSlice([]string{
					"IPv4",
					"IPv6",
				}, false),
			},
		},
	}
}

type IPCollection struct {
	Kind       interface{} `json:"kind"`
	APIVersion interface{} `json:"api-version"`
	Meta       struct {
		Name        string      `json:"name"`
		DisplayName string      `json:"display-name"`
		Tenant      string      `json:"tenant"`
		Namespace   interface{} `json:"namespace"`
		UUID        string      `json:"uuid"`
	} `json:"meta"`
	Spec struct {
		Addresses     []string `json:"addresses"`
		IPCollections []string `json:"ipcollections"`
		AddressFamily string   `json:"AddressFamily"`
	} `json:"spec"`
}

func resourceIPCollectionCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	ipCollection := &IPCollection{}
	ipCollection.Meta.DisplayName = d.Get("display_name").(string)
	ipCollection.Meta.Tenant = d.Get("tenant").(string)
	ipCollection.Spec.AddressFamily = d.Get("address_family").(string)

	if addresses, ok := d.GetOk("addresses"); ok {
		for _, addr := range addresses.([]interface{}) {
			ipCollection.Spec.Addresses = append(ipCollection.Spec.Addresses, addr.(string))
		}
	}
	if ipcollections, ok := d.GetOk("ip_collections"); ok {
		for _, coll := range ipcollections.([]interface{}) {
			ipCollection.Spec.IPCollections = append(ipCollection.Spec.IPCollections, coll.(string))
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

	d.SetId(responseIPCollection.Meta.UUID)
	d.Set("name", responseIPCollection.Meta.Name)
	d.Set("address_family", responseIPCollection.Spec.AddressFamily)

	return resourceIPCollectionRead(ctx, d, m)
}

func resourceIPCollectionRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := fmt.Sprintf("%s/configs/network/v1/tenant/default/ipcollections/%s", config.Server, d.Id())

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
		return diag.Errorf("failed to read ip_collection: HTTP %s", resp.Status)
	}

	ipCollection := &IPCollection{}
	if err := json.NewDecoder(resp.Body).Decode(ipCollection); err != nil {
		return diag.FromErr(err)
	}

	d.Set("display_name", ipCollection.Meta.DisplayName)
	d.Set("name", ipCollection.Meta.Name)
	d.Set("tenant", ipCollection.Meta.Tenant)
	d.Set("addresses", ipCollection.Spec.Addresses)
	d.Set("ip_collections", ipCollection.Spec.IPCollections)
	d.Set("address_family", ipCollection.Spec.AddressFamily)

	return nil
}

func resourceIPCollectionUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	ipCollection := &IPCollection{}
	ipCollection.Meta.Name = d.Id()
	ipCollection.Meta.DisplayName = d.Get("display_name").(string)
	ipCollection.Meta.Tenant = d.Get("tenant").(string)
	ipCollection.Spec.AddressFamily = d.Get("address_family").(string)

	addresses := d.Get("addresses").([]interface{})
	ipCollection.Spec.Addresses = make([]string, len(addresses))
	for i, addr := range addresses {
		ipCollection.Spec.Addresses[i] = addr.(string)
	}

	ipCollections := d.Get("ip_collections").([]interface{})
	ipCollection.Spec.IPCollections = make([]string, len(ipCollections))
	for i, coll := range ipCollections {
		ipCollection.Spec.IPCollections[i] = coll.(string)
	}

	jsonBytes, err := json.Marshal(ipCollection)
	if err != nil {
		return diag.FromErr(err)
	}

	url := fmt.Sprintf("%s/configs/network/v1/tenant/default/ipcollections/%s", config.Server, d.Id())
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonBytes))
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
		return diag.Errorf("failed to update ip_collection: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
	}

	return resourceIPCollectionRead(ctx, d, m)
}

func resourceIPCollectionDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := fmt.Sprintf("%s/configs/network/v1/tenant/default/ipcollections/%s", config.Server, d.Id())

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

	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("failed to delete ip_collection: HTTP %s", resp.Status)
	}

	d.SetId("")

	return nil
}
