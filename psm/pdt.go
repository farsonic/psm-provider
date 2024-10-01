package psm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourcePolicyDistributionTarget() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourcePolicyDistributionTargetCreate,
		ReadContext:   resourcePolicyDistributionTargetRead,
		UpdateContext: resourcePolicyDistributionTargetUpdate,
		DeleteContext: resourcePolicyDistributionTargetDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourcePolicyDistributionTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"dses": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

type PolicyDistributionTarget struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api-version"`
	Meta       struct {
		Name         string `json:"name"`
		Tenant       string `json:"tenant"`
		Namespace    string `json:"namespace"`
		GenerationID string `json:"generation-id"`
		UUID         string `json:"uuid"`
		SelfLink     string `json:"self-link"`
	} `json:"meta"`
	Spec struct {
		DSEs []string `json:"dses,omitempty"`
	} `json:"spec"`
}

func resourcePolicyDistributionTargetCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	pdt := &PolicyDistributionTarget{
		Kind:       "PolicyDistributionTarget",
		APIVersion: "v1",
	}
	pdt.Meta.Name = d.Get("name").(string)
	pdt.Meta.Tenant = "default"
	pdt.Meta.Namespace = "default"

	jsonData, err := json.Marshal(pdt)
	if err != nil {
		return diag.FromErr(err)
	}

	url := fmt.Sprintf("%s/configs/cluster/v1/tenant/default/policydistributiontargets", config.Server)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(jsonData)))
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

	if res.StatusCode != http.StatusOK {
		return diag.Errorf("failed to create PDT: HTTP %d", res.StatusCode)
	}

	var createdPDT PolicyDistributionTarget
	if err := json.NewDecoder(res.Body).Decode(&createdPDT); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdPDT.Meta.UUID)

	if _, ok := d.GetOk("dses"); ok {
		return resourcePolicyDistributionTargetUpdate(ctx, d, m)
	}

	return resourcePolicyDistributionTargetRead(ctx, d, m)
}

func resourcePolicyDistributionTargetRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	name := d.Get("name").(string)
	url := fmt.Sprintf("%s/configs/cluster/v1/tenant/default/policydistributiontargets/%s", config.Server, name)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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
		return diag.Errorf("failed to read PDT: HTTP %d", res.StatusCode)
	}

	var pdt PolicyDistributionTarget
	if err := json.NewDecoder(res.Body).Decode(&pdt); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", pdt.Meta.Name)
	d.Set("dses", pdt.Spec.DSEs)

	return nil
}

func resourcePolicyDistributionTargetUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	name := d.Get("name").(string)
	url := fmt.Sprintf("%s/configs/cluster/v1/tenant/default/policydistributiontargets/%s", config.Server, name)

	pdt := &PolicyDistributionTarget{
		Kind:       "PolicyDistributionTarget",
		APIVersion: "v1",
	}
	pdt.Meta.Name = name
	pdt.Meta.Tenant = "default"
	pdt.Meta.Namespace = "default"

	if v, ok := d.GetOk("dses"); ok {
		dses := v.(*schema.Set).List()
		pdt.Spec.DSEs = make([]string, len(dses))
		for i, dse := range dses {
			pdt.Spec.DSEs[i] = dse.(string)
		}
	}

	jsonData, err := json.Marshal(pdt)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", url, strings.NewReader(string(jsonData)))
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

	if res.StatusCode != http.StatusOK {
		return diag.Errorf("failed to update PDT: HTTP %d", res.StatusCode)
	}

	return resourcePolicyDistributionTargetRead(ctx, d, m)
}

func resourcePolicyDistributionTargetDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	name := d.Get("name").(string)
	url := fmt.Sprintf("%s/configs/cluster/v1/tenant/default/policydistributiontargets/%s", config.Server, name)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	res, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return diag.Errorf("failed to delete PDT: HTTP %d", res.StatusCode)
	}

	d.SetId("")

	return nil
}

func resourcePolicyDistributionTargetImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	config := m.(*Config)
	client := config.Client()

	name := d.Id()
	url := fmt.Sprintf("%s/configs/cluster/v1/tenant/default/policydistributiontargets/%s", config.Server, name)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to import PDT: HTTP %d", res.StatusCode)
	}

	var pdt PolicyDistributionTarget
	if err := json.NewDecoder(res.Body).Decode(&pdt); err != nil {
		return nil, err
	}

	d.SetId(pdt.Meta.UUID)
	d.Set("name", pdt.Meta.Name)
	if err := d.Set("dses", pdt.Spec.DSEs); err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
