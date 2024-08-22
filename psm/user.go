package psm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceUser() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceUserCreate,
		ReadContext:   resourceUserRead,
		UpdateContext: resourceUserUpdate,
		DeleteContext: resourceUserDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceUserImport,
		},
		Schema: map[string]*schema.Schema{
			"namespace": {
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
			"fullname": {
				Type:     schema.TypeString,
				Required: true,
			},
			"email": {
				Type:     schema.TypeString,
				Required: true,
			},
			"password": {
				Type:      schema.TypeString,
				Required:  true,
				Sensitive: true,
			},
			"type": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "local",
			},
			"tenant": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "default",
			},
			"authenticators": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"failed_login_attempts": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"locked": {
				Type:     schema.TypeBool,
				Computed: true,
			},
		},
	}
}

type User struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api-version"`
	Meta       struct {
		Name         string `json:"name"`
		Tenant       string `json:"tenant"`
		Namespace    string `json:"namespace"`
		GenerationID string `json:"generation-id"`
		UUID         string `json:"uuid"`
		CreationTime string `json:"creation-time"`
		ModTime      string `json:"mod-time"`
		SelfLink     string `json:"self-link"`
	} `json:"meta"`
	Spec struct {
		Fullname string `json:"fullname"`
		Email    string `json:"email"`
		Password string `json:"password,omitempty"`
		Type     string `json:"type"`
	} `json:"spec"`
	Status struct {
		Authenticators      []string `json:"authenticators"`
		FailedLoginAttempts int      `json:"failed-login-attempts"`
		Locked              bool     `json:"locked"`
	} `json:"status"`
}

func resourceUserCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	user := &User{
		Kind:       "User",
		APIVersion: "v1",
		Meta: struct {
			Name         string `json:"name"`
			Tenant       string `json:"tenant"`
			Namespace    string `json:"namespace"`
			GenerationID string `json:"generation-id"`
			UUID         string `json:"uuid"`
			CreationTime string `json:"creation-time"`
			ModTime      string `json:"mod-time"`
			SelfLink     string `json:"self-link"`
		}{
			Name:      d.Get("name").(string),
			Tenant:    d.Get("tenant").(string),
			Namespace: "default",
		},
		Spec: struct {
			Fullname string `json:"fullname"`
			Email    string `json:"email"`
			Password string `json:"password,omitempty"`
			Type     string `json:"type"`
		}{
			Fullname: d.Get("fullname").(string),
			Email:    d.Get("email").(string),
			Password: d.Get("password").(string),
			Type:     d.Get("type").(string),
		},
		Status: struct {
			Authenticators      []string `json:"authenticators"`
			FailedLoginAttempts int      `json:"failed-login-attempts"`
			Locked              bool     `json:"locked"`
		}{
			Authenticators: []string{"local"},
		},
	}

	jsonData, err := json.Marshal(user)
	if err != nil {
		return diag.FromErr(err)
	}

	tenant := d.Get("tenant").(string)
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/configs/auth/v1/tenant/%s/users", config.Server, tenant), bytes.NewBuffer(jsonData))
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

		// Check if the error is due to an existing user
		if res.StatusCode == http.StatusConflict {
			return diag.Errorf("failed to create user: user '%s' already exists in tenant '%s'. Use a different username or import the existing user", d.Get("name").(string), d.Get("tenant").(string))
		}

		return diag.Errorf("failed to create user: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var createdUser User
	if err := json.NewDecoder(res.Body).Decode(&createdUser); err != nil {
		return diag.FromErr(err)
	}

	d.SetId(createdUser.Meta.UUID)

	return resourceUserRead(ctx, d, m)
}

func resourceUserRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	tenant := d.Get("tenant").(string)
	namespace := d.Get("namespace").(string)
	name := d.Get("name").(string)

	tflog.Info(ctx, "Reading user", map[string]interface{}{
		"tenant":    tenant,
		"namespace": namespace,
		"name":      name,
	})

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/auth/v1/tenant/%s/users/%s", config.Server, tenant, name), nil)
	if err != nil {
		return diag.FromErr(err)
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	res, err := client.Do(req)
	if err != nil {
		tflog.Error(ctx, "Error making request", map[string]interface{}{"error": err.Error()})
		return diag.FromErr(err)
	}
	defer res.Body.Close()

	tflog.Info(ctx, "Received response", map[string]interface{}{"status": res.StatusCode})

	if res.StatusCode == http.StatusNotFound {
		tflog.Warn(ctx, "User not found", map[string]interface{}{"name": name})
		d.SetId("")
		return nil
	}

	if res.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			tflog.Error(ctx, "Failed to read error response body", map[string]interface{}{"error": err.Error()})
			return diag.Errorf("failed to read error response body: %v", err)
		}
		tflog.Error(ctx, "Failed to read user", map[string]interface{}{
			"status": res.StatusCode,
			"body":   string(bodyBytes),
		})
		return diag.Errorf("failed to read user: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var user User
	if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
		tflog.Error(ctx, "Failed to decode user", map[string]interface{}{"error": err.Error()})
		return diag.FromErr(err)
	}

	tflog.Info(ctx, "Successfully read user", map[string]interface{}{"user": user})

	d.Set("name", user.Meta.Name)
	d.Set("fullname", user.Spec.Fullname)
	d.Set("email", user.Spec.Email)
	d.Set("type", user.Spec.Type)
	d.Set("tenant", user.Meta.Tenant)
	d.Set("namespace", user.Meta.Namespace)
	d.Set("authenticators", user.Status.Authenticators)
	d.Set("failed_login_attempts", user.Status.FailedLoginAttempts)
	d.Set("locked", user.Status.Locked)

	return nil
}

func resourceUserUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	user := &User{
		Meta: struct {
			Name         string `json:"name"`
			Tenant       string `json:"tenant"`
			Namespace    string `json:"namespace"`
			GenerationID string `json:"generation-id"`
			UUID         string `json:"uuid"`
			CreationTime string `json:"creation-time"`
			ModTime      string `json:"mod-time"`
			SelfLink     string `json:"self-link"`
		}{
			Name: d.Get("name").(string),
		},
		Spec: struct {
			Fullname string `json:"fullname"`
			Email    string `json:"email"`
			Password string `json:"password,omitempty"`
			Type     string `json:"type"`
		}{
			Fullname: d.Get("fullname").(string),
			Email:    d.Get("email").(string),
			Type:     d.Get("type").(string),
		},
	}

	if d.HasChange("password") {
		user.Spec.Password = d.Get("password").(string)
	}

	jsonData, err := json.Marshal(user)
	if err != nil {
		return diag.FromErr(err)
	}

	tenant := d.Get("tenant").(string)
	name := d.Get("name").(string)
	req, err := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s/configs/auth/v1/tenant/%s/users/%s", config.Server, tenant, name), bytes.NewBuffer(jsonData))
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
		return diag.Errorf("failed to update user: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	return resourceUserRead(ctx, d, m)
}

func resourceUserDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	tenant := d.Get("tenant").(string)
	name := d.Get("name").(string)
	req, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s/configs/auth/v1/tenant/%s/users/%s", config.Server, tenant, name), nil)
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
		return diag.Errorf("failed to delete user: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	if res.StatusCode == http.StatusOK {
		readReq, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/auth/v1/tenant/%s/users/%s", config.Server, tenant, name), nil)
		if err != nil {
			return diag.FromErr(err)
		}
		readReq.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})
		readRes, err := client.Do(readReq)
		if err != nil {
			return diag.FromErr(err)
		}
		defer readRes.Body.Close()

		// If the user still exists, return an error
		if readRes.StatusCode == http.StatusOK {
			return diag.Errorf("failed to delete user: user still exists after deletion")
		}
	}

	d.SetId("")

	return nil
}

func resourceUserImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	config := m.(*Config)
	client := config.Client()

	parts := strings.Split(d.Id(), "/")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid import ID, should be in the format 'tenant/namespace/username'")
	}

	tenant := parts[0]
	name := parts[2]

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/auth/v1/tenant/%s/users/%s", config.Server, tenant, name), nil)
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
		return nil, fmt.Errorf("failed to import user: HTTP %d - %s", res.StatusCode, string(bodyBytes))
	}

	var user User
	if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
		return nil, err
	}

	d.SetId(user.Meta.UUID)
	d.Set("name", user.Meta.Name)
	d.Set("fullname", user.Spec.Fullname)
	d.Set("email", user.Spec.Email)
	d.Set("type", user.Spec.Type)
	d.Set("tenant", user.Meta.Tenant)
	d.Set("authenticators", user.Status.Authenticators)
	d.Set("failed_login_attempts", user.Status.FailedLoginAttempts)
	d.Set("locked", user.Status.Locked)

	return []*schema.ResourceData{d}, nil
}
