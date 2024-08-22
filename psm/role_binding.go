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

func resourceRoleBinding() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceRoleBindingCreate,
		ReadContext:   resourceRoleBindingRead,
		UpdateContext: resourceRoleBindingUpdate,
		DeleteContext: resourceRoleBindingDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceRoleBindingImport,
		},
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
			"namespace": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "default",
			},
			"users": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"user_groups": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"role": {
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

type RoleBinding struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api-version"`
	Meta       struct {
		Name            string      `json:"name"`
		Tenant          string      `json:"tenant"`
		Namespace       string      `json:"namespace"`
		GenerationID    string      `json:"generation-id"`
		ResourceVersion string      `json:"resource-version"`
		UUID            string      `json:"uuid"`
		Labels          interface{} `json:"labels"`
		CreationTime    string      `json:"creation-time"`
		ModTime         string      `json:"mod-time"`
		SelfLink        string      `json:"self-link"`
		DisplayName     string      `json:"display-name"`
	} `json:"meta"`
	Spec struct {
		Users      []string `json:"users"`
		UserGroups []string `json:"user-groups"`
		Role       string   `json:"role"`
	} `json:"spec"`
}

func resourceRoleBindingCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	roleBinding := &RoleBinding{
		Kind:       "RoleBindingList",
		APIVersion: "v1",
		Meta: struct {
			Name            string      `json:"name"`
			Tenant          string      `json:"tenant"`
			Namespace       string      `json:"namespace"`
			GenerationID    string      `json:"generation-id"`
			ResourceVersion string      `json:"resource-version"`
			UUID            string      `json:"uuid"`
			Labels          interface{} `json:"labels"`
			CreationTime    string      `json:"creation-time"`
			ModTime         string      `json:"mod-time"`
			SelfLink        string      `json:"self-link"`
			DisplayName     string      `json:"display-name"`
		}{
			Name:      d.Get("name").(string),
			Tenant:    d.Get("tenant").(string),
			Namespace: d.Get("namespace").(string),
		},
		Spec: struct {
			Users      []string `json:"users"`
			UserGroups []string `json:"user-groups"`
			Role       string   `json:"role"`
		}{
			Users:      ExpandStringSet(d.Get("users").(*schema.Set)),
			UserGroups: ExpandStringSet(d.Get("user_groups").(*schema.Set)),
			Role:       d.Get("role").(string),
		},
	}

	jsonData, err := json.Marshal(roleBinding)
	if err != nil {
		return diag.FromErr(err)
	}

	tenant := d.Get("tenant").(string)
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/configs/auth/v1/tenant/%s/role-bindings", config.Server, tenant), bytes.NewBuffer(jsonData))
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

	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return diag.Errorf("failed to read error response body: %v", err)
		}
		return diag.Errorf("failed to create role binding: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var createdRoleBinding RoleBinding
	if err := json.NewDecoder(res.Body).Decode(&createdRoleBinding); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdRoleBinding.Meta.UUID)

	return resourceRoleBindingRead(ctx, d, m)
}

func resourceRoleBindingRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	tenant := d.Get("tenant").(string)
	name := d.Get("name").(string)
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/auth/v1/tenant/%s/role-bindings/%s", config.Server, tenant, name), nil)
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
		return diag.Errorf("failed to read role binding: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var roleBinding RoleBinding
	if err := json.NewDecoder(res.Body).Decode(&roleBinding); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", roleBinding.Meta.Name)
	d.Set("tenant", roleBinding.Meta.Tenant)
	d.Set("namespace", roleBinding.Meta.Namespace)
	d.Set("users", roleBinding.Spec.Users)
	d.Set("user_groups", roleBinding.Spec.UserGroups)
	d.Set("role", roleBinding.Spec.Role)

	return nil
}

func resourceRoleBindingUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	roleBinding := &RoleBinding{
		Kind:       "RoleBindingList",
		APIVersion: "v1",
		Meta: struct {
			Name            string      `json:"name"`
			Tenant          string      `json:"tenant"`
			Namespace       string      `json:"namespace"`
			GenerationID    string      `json:"generation-id"`
			ResourceVersion string      `json:"resource-version"`
			UUID            string      `json:"uuid"`
			Labels          interface{} `json:"labels"`
			CreationTime    string      `json:"creation-time"`
			ModTime         string      `json:"mod-time"`
			SelfLink        string      `json:"self-link"`
			DisplayName     string      `json:"display-name"`
		}{
			Name:      d.Get("name").(string),
			Tenant:    d.Get("tenant").(string),
			Namespace: d.Get("namespace").(string),
		},
		Spec: struct {
			Users      []string `json:"users"`
			UserGroups []string `json:"user-groups"`
			Role       string   `json:"role"`
		}{
			Users:      ExpandStringSet(d.Get("users").(*schema.Set)),
			UserGroups: ExpandStringSet(d.Get("user_groups").(*schema.Set)),
			Role:       d.Get("role").(string),
		},
	}

	jsonData, err := json.Marshal(roleBinding)
	if err != nil {
		return diag.FromErr(err)
	}

	tenant := d.Get("tenant").(string)
	name := d.Get("name").(string)
	req, err := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s/configs/auth/v1/tenant/%s/role-bindings/%s", config.Server, tenant, name), bytes.NewBuffer(jsonData))
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
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return diag.Errorf("failed to read error response body: %v", err)
		}
		return diag.Errorf("failed to update role binding: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	return resourceRoleBindingRead(ctx, d, m)
}

func resourceRoleBindingDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	tenant := d.Get("tenant").(string)
	name := d.Get("name").(string)
	req, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s/configs/auth/v1/tenant/%s/role-bindings/%s", config.Server, tenant, name), nil)
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	res, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return diag.Errorf("failed to read error response body: %v", err)
		}
		return diag.Errorf("failed to delete role binding: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	d.SetId("")
	return nil
}

func resourceRoleBindingImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	config := m.(*Config)
	client := config.Client()

	parts := strings.Split(d.Id(), "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid import ID, should be in the format 'tenant/name'")
	}

	tenant := parts[0]
	name := parts[1]

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/auth/v1/tenant/%s/role-bindings/%s", config.Server, tenant, name), nil)
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
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read error response body: %v", err)
		}
		return nil, fmt.Errorf("failed to import role binding: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var roleBinding RoleBinding
	if err := json.NewDecoder(res.Body).Decode(&roleBinding); err != nil {
		return nil, err
	}

	d.SetId(roleBinding.Meta.UUID)
	d.Set("name", roleBinding.Meta.Name)
	d.Set("tenant", roleBinding.Meta.Tenant)
	d.Set("namespace", roleBinding.Meta.Namespace)
	d.Set("users", roleBinding.Spec.Users)
	d.Set("user_groups", roleBinding.Spec.UserGroups)
	d.Set("role", roleBinding.Spec.Role)

	return []*schema.ResourceData{d}, nil
}
