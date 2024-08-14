package psm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceRuleProfile() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceRuleProfileCreate,
		ReadContext:   resourceRuleProfileRead,
		UpdateContext: resourceRuleProfileUpdate,
		DeleteContext: resourceRuleProfileDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"conn_track": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "inherit",
				ValidateFunc: validation.StringInSlice([]string{
					"inherit",
					"enable",
					"disable",
				}, false),
			},
			"allow_session_reuse": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "inherit",
				ValidateFunc: validation.StringInSlice([]string{
					"inherit",
					"enable",
					"disable",
				}, false),
			},
		},
	}
}

type RuleProfile struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api-version"`
	Meta       struct {
		Name string `json:"name"`
	} `json:"meta"`
	Spec struct {
		ConnTrack         string `json:"conn-track"`
		AllowSessionReuse string `json:"allow-session-reuse"`
	} `json:"spec"`
}

func resourceRuleProfileCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	ruleProfile := &RuleProfile{
		Kind:       "RuleProfile",
		APIVersion: "v1",
	}

	ruleProfile.Meta.Name = d.Get("name").(string)
	ruleProfile.Spec.ConnTrack = d.Get("conn_track").(string)
	ruleProfile.Spec.AllowSessionReuse = d.Get("allow_session_reuse").(string)

	jsonData, err := json.Marshal(ruleProfile)
	if err != nil {
		return diag.FromErr(err)
	}

	url := fmt.Sprintf("%s/configs/security/v1/tenant/default/ruleProfiles", config.Server)
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
		bodyBytes, _ := io.ReadAll(res.Body)
		return diag.Errorf("failed to create rule profile: %s. Response: %s", res.Status, string(bodyBytes))
	}

	var createdRuleProfile RuleProfile
	if err := json.NewDecoder(res.Body).Decode(&createdRuleProfile); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdRuleProfile.Meta.Name)

	return resourceRuleProfileRead(ctx, d, m)
}

func resourceRuleProfileRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := fmt.Sprintf("%s/configs/security/v1/tenant/default/ruleProfiles/%s", config.Server, d.Id())

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
		return diag.Errorf("failed to read rule profile: %s", res.Status)
	}

	var ruleProfile RuleProfile
	if err := json.NewDecoder(res.Body).Decode(&ruleProfile); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", ruleProfile.Meta.Name)
	d.Set("conn_track", ruleProfile.Spec.ConnTrack)
	d.Set("allow_session_reuse", ruleProfile.Spec.AllowSessionReuse)

	return nil
}

func resourceRuleProfileUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	ruleProfile := &RuleProfile{
		Kind:       "RuleProfile",
		APIVersion: "v1",
	}

	ruleProfile.Meta.Name = d.Get("name").(string)
	ruleProfile.Spec.ConnTrack = d.Get("conn_track").(string)
	ruleProfile.Spec.AllowSessionReuse = d.Get("allow_session_reuse").(string)

	jsonData, err := json.Marshal(ruleProfile)
	if err != nil {
		return diag.FromErr(err)
	}

	url := fmt.Sprintf("%s/configs/security/v1/tenant/default/ruleProfiles/%s", config.Server, d.Id())
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
		return diag.Errorf("failed to update rule profile: %s", res.Status)
	}

	return resourceRuleProfileRead(ctx, d, m)
}

func resourceRuleProfileDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := fmt.Sprintf("%s/configs/security/v1/tenant/default/ruleProfiles/%s", config.Server, d.Id())

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
		return diag.Errorf("failed to delete rule profile: %s", res.Status)
	}

	d.SetId("")

	return nil
}
