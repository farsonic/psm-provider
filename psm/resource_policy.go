package psm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourcePolicy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourcePolicyCreate,
		ReadContext:   resourcePolicyRead,
		DeleteContext: resourcePolicyDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"tenant": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "default",
				ForceNew: true,
			},
			"pdt": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "default",
				ForceNew: true,
			},
		},
	}
}

type Policy struct {
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
		AttachTenant              bool        `json:"attach-tenant "default:true`
		Priority                  interface{} `json:"priority"`
		PolicyDistributionTargets []string    `json:"policy-distribution-targets"`
	} `json:"spec"`
}

func resourcePolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	policy := &Policy{}
	policy.Meta.Name = d.Get("name").(string)
	policy.Meta.Tenant = d.Get("tenant").(string)
	policy.Spec.PolicyDistributionTargets = []string{d.Get("pdt").(string)}

	jsonBytes, err := json.Marshal(policy)
	if err != nil {
		return diag.FromErr(err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", config.Server+"/configs/security/v1/tenant/default/networksecuritypolicies", bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(err)
	}
	log.Printf("[DEBUG] JSON being sent to the server: %s", string(jsonBytes))

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return diag.Errorf("failed to create policy: HTTP %d %s: %s", resp.StatusCode, resp.Status, bodyBytes)
	}

	responsePolicy := &Policy{}
	if err := json.NewDecoder(resp.Body).Decode(responsePolicy); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(responsePolicy.Meta.UUID.(string))

	return resourcePolicyRead(ctx, d, m)
}

func resourcePolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/security/v1/tenant/default/networksecuritypolicies/" + d.Get("name").(string)

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
		return diag.Errorf("failed to read policy: HTTP %s", resp.Status)
	}

	policy := &Policy{}
	if err := json.NewDecoder(resp.Body).Decode(policy); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", policy.Meta.Name)
	d.Set("tenant", policy.Meta.Tenant)
	d.Set("pdt", policy.Spec.PolicyDistributionTargets)
	if len(policy.Spec.PolicyDistributionTargets) > 0 {
		d.Set("pdt", policy.Spec.PolicyDistributionTargets[0])
	}

	return nil
}

func resourcePolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := config.Server + "/configs/security/v1/tenant/default/networksecuritypolicies/" + d.Get("name").(string)

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
		return diag.Errorf("failed to delete policy: HTTP %s", resp.Status)
	}

	d.SetId("")

	return nil
}
