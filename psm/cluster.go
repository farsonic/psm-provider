package psm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceCluster() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceClusterCreate,
		ReadContext:   resourceClusterRead,
		UpdateContext: resourceClusterUpdate,
		DeleteContext: resourceClusterDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceClusterImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"quorum_nodes": {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
				Computed: true,
			},
			"virtual_ip": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"ntp_servers": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"auto_admit_dscs": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"certs": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"key": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
			},
			"bootstrap_ipam_policy": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"sites": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"labels": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"certificate": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
		},
	}
}

type Cluster struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api-version"`
	Meta       struct {
		Name            string            `json:"name"`
		Tenant          interface{}       `json:"tenant"`
		Namespace       interface{}       `json:"namespace"`
		GenerationID    string            `json:"generation-id"`
		ResourceVersion string            `json:"resource-version"`
		UUID            string            `json:"uuid"`
		Labels          map[string]string `json:"labels"`
		SelfLink        string            `json:"self-link"`
		DisplayName     interface{}       `json:"display-name"`
	} `json:"meta"`
	Spec struct {
		QuorumNodes         []string    `json:"quorum-nodes"`
		VirtualIP           interface{} `json:"virtual-ip"`
		NTPServers          []string    `json:"ntp-servers"`
		AutoAdmitDSCs       bool        `json:"auto-admit-dscs"`
		Certs               string      `json:"certs"`
		Key                 interface{} `json:"key"`
		BootstrapIPAMPolicy interface{} `json:"bootstrap-ipam-policy"`
		Certificate         string      `json:"certificate"`
	} `json:"spec"`
}

func resourceClusterCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	cluster := &Cluster{
		Kind:       "Cluster",
		APIVersion: "v1",
	}

	// Initialize the Labels map
	cluster.Meta.Labels = make(map[string]string)

	cluster.Meta.Name = d.Get("name").(string)
	if v, ok := d.GetOk("quorum_nodes"); ok {
		cluster.Spec.QuorumNodes = expandStringList(v.([]interface{}))
	}
	if v, ok := d.GetOk("virtual_ip"); ok {
		cluster.Spec.VirtualIP = v.(string)
	}
	if v, ok := d.GetOk("ntp_servers"); ok {
		cluster.Spec.NTPServers = expandStringList(v.([]interface{}))
	}
	cluster.Spec.AutoAdmitDSCs = d.Get("auto_admit_dscs").(bool)
	cluster.Spec.Certs = d.Get("certs").(string)
	if v, ok := d.GetOk("key"); ok {
		cluster.Spec.Key = v.(string)
	}
	if v, ok := d.GetOk("bootstrap_ipam_policy"); ok {
		cluster.Spec.BootstrapIPAMPolicy = v.(string)
	}
	if v, ok := d.GetOk("certificate"); ok {
		cluster.Spec.Certificate = v.(string)
	}

	// Handle sites and system.multisite label
	if sites, ok := d.GetOk("sites"); ok {
		siteList := sites.([]interface{})
		siteStrings := make([]string, len(siteList))
		for i, v := range siteList {
			siteStrings[i] = v.(string)
		}
		cluster.Meta.Labels["system.multisite"] = strings.Join(siteStrings, "|||")
	}

	jsonData, err := json.Marshal(cluster)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s/configs/cluster/v1/cluster", config.Server), bytes.NewBuffer(jsonData))
	if err != nil {
		return diag.FromErr(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	res, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusPreconditionFailed {
		return diag.Errorf("Cluster configuration already exists. Use 'terraform import' to manage existing cluster or remove the existing configuration.")
	}

	if res.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return diag.Errorf("failed to read error response body: %v", err)
		}
		return diag.Errorf("failed to create cluster: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var createdCluster Cluster
	if err := json.NewDecoder(res.Body).Decode(&createdCluster); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdCluster.Meta.UUID)

	return resourceClusterRead(ctx, d, m)
}

func resourceClusterRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/cluster/v1/cluster", config.Server), nil)
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	res, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotFound {
		d.SetId("")
		return nil
	}

	if res.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return diag.Errorf("failed to read error response body: %v", err)
		}
		return diag.Errorf("failed to read cluster: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var cluster Cluster
	if err := json.NewDecoder(res.Body).Decode(&cluster); err != nil {
		return diag.FromErr(err)
	}

	if multisite, ok := cluster.Meta.Labels["system.multisite"]; ok {
		sites := strings.Split(multisite, "|||")
		if err := d.Set("sites", sites); err != nil {
			return diag.FromErr(err)
		}
	}

	d.Set("name", cluster.Meta.Name)
	d.Set("quorum_nodes", cluster.Spec.QuorumNodes)
	d.Set("virtual_ip", cluster.Spec.VirtualIP)
	d.Set("ntp_servers", cluster.Spec.NTPServers)
	d.Set("auto_admit_dscs", cluster.Spec.AutoAdmitDSCs)
	d.Set("certs", cluster.Spec.Certs)
	d.Set("bootstrap_ipam_policy", cluster.Spec.BootstrapIPAMPolicy)
	d.Set("certificate", cluster.Spec.Certificate)

	return nil
}

func resourceClusterUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	cluster := &Cluster{
		Kind:       "Cluster",
		APIVersion: "v1",
	}

	// Initialize the Labels map
	cluster.Meta.Labels = make(map[string]string)

	cluster.Meta.Name = d.Get("name").(string)
	if v, ok := d.GetOk("quorum_nodes"); ok {
		cluster.Spec.QuorumNodes = expandStringList(v.([]interface{}))
	}
	if v, ok := d.GetOk("virtual_ip"); ok {
		cluster.Spec.VirtualIP = v.(string)
	}
	if v, ok := d.GetOk("ntp_servers"); ok {
		cluster.Spec.NTPServers = expandStringList(v.([]interface{}))
	}
	cluster.Spec.AutoAdmitDSCs = d.Get("auto_admit_dscs").(bool)
	cluster.Spec.Certs = d.Get("certs").(string)
	if v, ok := d.GetOk("key"); ok {
		cluster.Spec.Key = v.(string)
	}
	if v, ok := d.GetOk("bootstrap_ipam_policy"); ok {
		cluster.Spec.BootstrapIPAMPolicy = v.(string)
	}
	if v, ok := d.GetOk("certificate"); ok {
		cluster.Spec.Certificate = v.(string)
	}

	// Handle sites and system.multisite label
	if sites, ok := d.GetOk("sites"); ok {
		siteList := sites.([]interface{})
		siteStrings := make([]string, len(siteList))
		for i, v := range siteList {
			siteStrings[i] = v.(string)
		}
		cluster.Meta.Labels["system.multisite"] = strings.Join(siteStrings, "|||")
	}

	jsonData, err := json.Marshal(cluster)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s/configs/cluster/v1/cluster", config.Server), bytes.NewBuffer(jsonData))
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
		return diag.Errorf("failed to update cluster: HTTP %d - %s", resp.StatusCode, string(bodyBytes))
	}

	return resourceClusterRead(ctx, d, m)
}

func resourceClusterDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Cluster resources typically can't be deleted, only modified
	// You may want to implement a custom delete behavior or return an error
	return diag.Errorf("Cluster resources cannot be deleted")
}

func resourceClusterImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	// Since there's only one cluster, we don't need an ID for import
	d.SetId("cluster")
	return []*schema.ResourceData{d}, nil
}
