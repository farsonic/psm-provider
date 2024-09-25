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

func resourceRole() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceRoleCreate,
		ReadContext:   resourceRoleRead,
		UpdateContext: resourceRoleUpdate,
		DeleteContext: resourceRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceRoleImport,
		},
		Schema: map[string]*schema.Schema{
			"tenant": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "default",
				ForceNew: true,
			},
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"namespace": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "default",
				ForceNew: true,
			},
			"permissions": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"resource_group": {
							Type:     schema.TypeString,
							Required: true,
						},
						"resource_kind": {
							Type:     schema.TypeString,
							Required: true,
						},
						"actions": {
							Type:     schema.TypeList,
							Required: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
		},
	}
}

type Role struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api-version"`
	Meta       struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UUID      string `json:"uuid"`
	} `json:"meta"`
	Spec struct {
		Permissions []struct {
			ResourceGroup     string   `json:"resource-group"`
			ResourceKind      string   `json:"resource-kind"`
			ResourceNamespace string   `json:"resource-namespace"`
			Actions           []string `json:"actions"`
		} `json:"permissions"`
	} `json:"spec"`
}

func resourceRoleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	role := &Role{
		Kind:       "Role",
		APIVersion: "v1",
		Meta: struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			UUID      string `json:"uuid"`
		}{
			Name:      d.Get("name").(string),
			Namespace: d.Get("namespace").(string),
		},
		Spec: struct {
			Permissions []struct {
				ResourceGroup     string   `json:"resource-group"`
				ResourceKind      string   `json:"resource-kind"`
				ResourceNamespace string   `json:"resource-namespace"`
				Actions           []string `json:"actions"`
			} `json:"permissions"`
		}{
			Permissions: expandPermissions(d.Get("permissions").([]interface{})),
		},
	}

	jsonData, err := json.Marshal(role)
	if err != nil {
		return diag.FromErr(err)
	}

	tenant := d.Get("tenant").(string)
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/configs/auth/v1/tenant/%s/roles", config.Server, tenant), bytes.NewBuffer(jsonData))

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
		return diag.Errorf("failed to create role: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var createdRole Role
	if err := json.NewDecoder(res.Body).Decode(&createdRole); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdRole.Meta.UUID)

	return resourceRoleRead(ctx, d, m)
}

func resourceRoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	name := d.Get("name").(string)

	tenant := d.Get("tenant").(string)
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/auth/v1/tenant/%s/roles/%s", config.Server, tenant, name), nil)

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
		return diag.Errorf("failed to read role: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var role Role
	if err := json.NewDecoder(res.Body).Decode(&role); err != nil {
		return diag.FromErr(err)
	}

	d.Set("name", role.Meta.Name)
	d.Set("namespace", role.Meta.Namespace)
	d.Set("permissions", flattenPermissions(role.Spec.Permissions))

	return nil
}

func resourceRoleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	role := &Role{
		Kind:       "Role",
		APIVersion: "v1",
		Meta: struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			UUID      string `json:"uuid"`
		}{
			Name:      d.Get("name").(string),
			Namespace: d.Get("namespace").(string),
		},
		Spec: struct {
			Permissions []struct {
				ResourceGroup     string   `json:"resource-group"`
				ResourceKind      string   `json:"resource-kind"`
				ResourceNamespace string   `json:"resource-namespace"`
				Actions           []string `json:"actions"`
			} `json:"permissions"`
		}{
			Permissions: expandPermissions(d.Get("permissions").([]interface{})),
		},
	}

	jsonData, err := json.Marshal(role)
	if err != nil {
		return diag.FromErr(err)
	}

	name := d.Get("name").(string)
	tenant := d.Get("tenant").(string)
	req, err := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s/configs/auth/v1/tenant/%s/roles/%s", config.Server, tenant, name), bytes.NewBuffer(jsonData))
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
		return diag.Errorf("failed to update role: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	return resourceRoleRead(ctx, d, m)
}

func resourceRoleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	name := d.Get("name").(string)
	tenant := d.Get("tenant").(string)
	req, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s/configs/auth/v1/tenant/%s/roles/%s", config.Server, tenant, name), nil)
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	res, err := client.Do(req)
	if err != nil {
		return diag.FromErr(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusNoContent && res.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return diag.Errorf("failed to read error response body: %v", err)
		}
		return diag.Errorf("failed to delete role: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	if res.StatusCode == http.StatusOK {
		readReq, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/auth/v1/tenant/%s/roles/%s", config.Server, tenant, name), nil)
		if err != nil {
			return diag.FromErr(err)
		}
		readReq.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})
		readRes, err := client.Do(readReq)
		if err != nil {
			return diag.FromErr(err)
		}
		defer readRes.Body.Close()

		// If the role still exists, return an error
		if readRes.StatusCode == http.StatusOK {
			return diag.Errorf("failed to delete role: role still exists after deletion")
		}
	}

	d.SetId("")

	return nil
}

func resourceRoleImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	config := m.(*Config)
	client := config.Client()

	parts := strings.Split(d.Id(), "/")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid import ID, should be in the format 'tenant/namespace/role_name'")
	}

	tenant := parts[0]
	namespace := parts[1]
	name := parts[2]

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/auth/v1/tenant/%s/roles/%s", config.Server, tenant, name), nil)
	if err != nil {
		return nil, err
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("role not found: %s", name)
	}

	if res.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read error response body: %v", err)
		}
		return nil, fmt.Errorf("failed to import role: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var role Role
	if err := json.NewDecoder(res.Body).Decode(&role); err != nil {
		return nil, err
	}

	d.SetId(role.Meta.UUID)
	d.Set("tenant", tenant)
	d.Set("name", role.Meta.Name)
	d.Set("namespace", namespace)
	d.Set("permissions", flattenPermissions(role.Spec.Permissions))

	return []*schema.ResourceData{d}, nil
}
