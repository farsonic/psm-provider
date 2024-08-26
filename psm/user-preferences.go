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

func resourcePSMUserPreferences() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourcePSMUserPreferencesCreateOrUpdate,
		ReadContext:   resourcePSMUserPreferencesRead,
		UpdateContext: resourcePSMUserPreferencesCreateOrUpdate,
		DeleteContext: resourcePSMUserPreferencesDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourcePSMUserPreferencesImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"timezone_utc": {
				Type:          schema.TypeBool,
				Optional:      true,
				ConflictsWith: []string{"timezone_name", "timezone_client"},
			},
			"timezone_name": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"timezone_utc", "timezone_client"},
			},
			"timezone_client": {
				Type:          schema.TypeBool,
				Optional:      true,
				ConflictsWith: []string{"timezone_utc", "timezone_name"},
			},
			"service_cards": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

type UserPreferences struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api-version"`
	Meta       struct {
		Name      string `json:"name"`
		Tenant    string `json:"tenant"`
		Namespace string `json:"namespace"`
	} `json:"meta"`
	Spec struct {
		Options string `json:"options"`
	} `json:"spec"`
}

type Options struct {
	Timezone  TimezoneOptions  `json:"timezone"`
	Dashboard DashboardOptions `json:"dashboard"`
}

type TimezoneOptions struct {
	Timezone       string `json:"timezone"`
	SetServerTime  bool   `json:"setServerTime"`
	ClientTimezone bool   `json:"clientTimezone"`
}

type DashboardOptions struct {
	DashboardCardState map[string]string `json:"dashboardCardState"`
}

func resourcePSMUserPreferencesCreateOrUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	userPreferences := &UserPreferences{
		Kind:       "UserPreference",
		APIVersion: "v1",
	}
	userPreferences.Meta.Name = d.Get("name").(string)
	userPreferences.Meta.Tenant = "default"
	userPreferences.Meta.Namespace = "default"

	options := Options{
		Timezone: TimezoneOptions{
			SetServerTime:  false,
			ClientTimezone: false,
		},
		Dashboard: DashboardOptions{
			DashboardCardState: make(map[string]string),
		},
	}

	if d.Get("timezone_utc").(bool) {
		options.Timezone.Timezone = "UTC"
	} else if name, ok := d.GetOk("timezone_name"); ok {
		options.Timezone.Timezone = name.(string)
	} else if d.Get("timezone_client").(bool) {
		options.Timezone.ClientTimezone = true
	}

	serviceCards := d.Get("service_cards").(*schema.Set)
	for _, card := range serviceCards.List() {
		options.Dashboard.DashboardCardState[card.(string)] = "active"
	}

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error marshalling Options: %v", err))
	}
	userPreferences.Spec.Options = string(optionsJSON)

	jsonBytes, err := json.Marshal(userPreferences)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error marshalling UserPreferences: %v", err))
	}

	url := fmt.Sprintf("%s/configs/auth/v1/tenant/default/user-preferences/admin", config.Server)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating request: %v", err))
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error making request: %v", err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error reading response body: %v", err))
	}

	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("API request failed: %s - %s", resp.Status, string(body))
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error parsing response body: %v", err))
	}

	d.SetId("admin")
	d.Set("name", "admin")

	return resourcePSMUserPreferencesRead(ctx, d, m)
}

func resourcePSMUserPreferencesRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	url := fmt.Sprintf("%s/configs/auth/v1/tenant/default/user-preferences/admin", config.Server)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating request: %v", err))
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error making request: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		d.SetId("")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return diag.Errorf("API request failed: %s", resp.Status)
	}

	var result UserPreferences
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error decoding response: %v", err))
	}

	var options Options
	err = json.Unmarshal([]byte(result.Spec.Options), &options)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error unmarshalling Options: %v", err))
	}

	d.Set("name", result.Meta.Name)
	d.Set("timezone", options.Timezone.Timezone)
	d.Set("set_server_time", options.Timezone.SetServerTime)
	d.Set("client_timezone", options.Timezone.ClientTimezone)

	if options.Timezone.Timezone == "UTC" {
		d.Set("timezone_utc", true)
	} else if options.Timezone.ClientTimezone {
		d.Set("timezone_client", true)
	} else {
		d.Set("timezone_name", options.Timezone.Timezone)
	}

	var serviceCards []string
	for card, state := range options.Dashboard.DashboardCardState {
		if state == "active" {
			serviceCards = append(serviceCards, card)
		}
	}
	d.Set("service_cards", serviceCards)

	return nil
}

func resourcePSMUserPreferencesDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// User preferences cannot be deleted, so we'll reset them to default values
	d.Set("timezone_utc", true)
	d.Set("timezone_name", nil)
	d.Set("timezone_client", false)
	d.Set("service_cards", []string{})

	return resourcePSMUserPreferencesCreateOrUpdate(ctx, d, m)
}

func resourcePSMUserPreferencesImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	config := m.(*Config)
	if config.Server == "" {
		return nil, fmt.Errorf("provider server configuration is required for import")
	}

	d.SetId(d.Get("name").(string))

	diags := resourcePSMUserPreferencesRead(ctx, d, m)
	if diags.HasError() {
		return nil, fmt.Errorf("error reading UserPreferences during import: %v", diags)
	}

	return []*schema.ResourceData{d}, nil
}
