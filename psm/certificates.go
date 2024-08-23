package psm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceCertificate() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceCertificateCreate,
		ReadContext:   resourceCertificateRead,
		UpdateContext: resourceCertificateUpdate,
		DeleteContext: resourceCertificateDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceCertificateImport,
		},
		Schema: map[string]*schema.Schema{
			"kind": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"api_version": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"certificate_data": {
				Type:     schema.TypeString,
				Required: true,
			},
			"private_key": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

type Certificate struct {
	Kind       *string         `json:"kind"`
	APIVersion *string         `json:"api-version"`
	Meta       CertificateMeta `json:"meta"`
	Spec       CertificateSpec `json:"spec"`
}

type CertificateMeta struct {
	Name        string  `json:"name"`
	Tenant      string  `json:"tenant,omitempty"`
	Namespace   string  `json:"namespace,omitempty"`
	UUID        *string `json:"uuid"`
	DisplayName string  `json:"display-name,omitempty"`
}

type CertificateSpec struct {
	CertificateData string `json:"certificate-data"`
	PrivateKey      string `json:"private-key,omitempty"`
	Description     string `json:"description"`
}

func resourceCertificateCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	name := d.Get("name").(string)
	cert := &Certificate{
		Kind:       stringPtr("Certificate"),
		APIVersion: stringPtr("v1"),
		Meta: CertificateMeta{
			Name: name,
		},
		Spec: CertificateSpec{
			CertificateData: d.Get("certificate_data").(string),
			PrivateKey:      d.Get("private_key").(string),
			Description:     d.Get("description").(string),
		},
	}

	jsonBytes, err := json.Marshal(cert)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error marshalling Certificate: %v", err))
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/configs/security/v1/tenant/default/certificates", config.Server), bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating request: %v", err))
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error sending request: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return diag.Errorf("error creating Certificate: API returned status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Set the ID to the certificate name
	d.SetId(name)

	// Wait for the certificate to be available
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return diag.FromErr(fmt.Errorf("timeout waiting for certificate to be created"))
		case <-ticker.C:
			// Try to read the certificate
			if diags := resourceCertificateRead(ctx, d, m); diags.HasError() {
				log.Printf("[DEBUG] Certificate not yet available, retrying...")
			} else {
				return diags
			}
		case <-ctx.Done():
			return diag.FromErr(ctx.Err())
		}
	}
}

func resourceCertificateRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	name := d.Id()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/security/v1/tenant/default/certificates/%s", config.Server, name), nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating request: %v", err))
	}

	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})
	response, err := client.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error sending request: %v", err))
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		// Certificate doesn't exist
		d.SetId("")
		return nil
	}

	if response.StatusCode != http.StatusOK {
		return diag.FromErr(fmt.Errorf("failed to read Certificate: HTTP %d", response.StatusCode))
	}

	var cert Certificate
	if err := json.NewDecoder(response.Body).Decode(&cert); err != nil {
		return diag.FromErr(fmt.Errorf("error decoding response: %v", err))
	}

	d.Set("kind", cert.Kind)
	d.Set("api_version", cert.APIVersion)
	d.Set("name", cert.Meta.Name)
	d.Set("certificate_data", cert.Spec.CertificateData)
	d.Set("description", cert.Spec.Description)

	log.Printf("[INFO] Successfully read certificate: %s", d.Id())
	return nil
}

func resourceCertificateUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	cert := &Certificate{
		Kind:       stringPtr("Certificate"),
		APIVersion: stringPtr("v1"),
		Meta: CertificateMeta{
			Name: d.Get("name").(string),
		},
		Spec: CertificateSpec{
			CertificateData: d.Get("certificate_data").(string),
			Description:     d.Get("description").(string),
		},
	}

	// Only include private_key if it's set in the configuration
	if v, ok := d.GetOk("private_key"); ok {
		cert.Spec.PrivateKey = v.(string)
	}

	jsonBytes, err := json.Marshal(cert)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error marshalling Certificate: %v", err))
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s/configs/security/v1/tenant/default/certificates/%s", config.Server, d.Id()), bytes.NewBuffer(jsonBytes))
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating request: %v", err))
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error sending request: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return diag.Errorf("error updating Certificate: API returned status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var updatedCert Certificate
	if err := json.NewDecoder(resp.Body).Decode(&updatedCert); err != nil {
		return diag.FromErr(fmt.Errorf("error decoding response: %v", err))
	}

	// Update the Terraform state with the returned data
	if err := d.Set("kind", updatedCert.Kind); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("api_version", updatedCert.APIVersion); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("name", updatedCert.Meta.Name); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("certificate_data", updatedCert.Spec.CertificateData); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("description", updatedCert.Spec.Description); err != nil {
		return diag.FromErr(err)
	}

	return resourceCertificateRead(ctx, d, m)
}

func resourceCertificateDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*Config)
	client := config.Client()

	name := d.Id()

	req, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s/configs/security/v1/tenant/default/certificates/%s", config.Server, name), nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error creating delete request: %v", err))
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	resp, err := client.Do(req)
	if err != nil {
		return diag.FromErr(fmt.Errorf("error sending delete request: %v", err))
	}
	defer resp.Body.Close()

	// Check for specific status codes
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusAccepted:
		// These status codes indicate successful deletion
		d.SetId("")
		return nil
	case http.StatusNotFound:
		// If the resource is already gone, we're fine
		d.SetId("")
		return nil
	default:
		// For any other status code, we'll treat it as an error
		bodyBytes, _ := io.ReadAll(resp.Body)
		return diag.Errorf("error deleting Certificate: API returned status code %d: %s", resp.StatusCode, string(bodyBytes))
	}
}

func resourceCertificateImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	config := m.(*Config)
	client := config.Client()

	// The import ID is expected to be the resource ID
	resourceID := d.Id()

	// Prepare the HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/configs/security/v1/tenant/default/certificates/%s", config.Server, resourceID), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating import request: %v", err)
	}

	// Set necessary headers
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sid", Value: config.SID})

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending import request: %v", err)
	}
	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("error importing Certificate: API returned status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Decode the response
	var importedCert Certificate
	if err := json.NewDecoder(resp.Body).Decode(&importedCert); err != nil {
		return nil, fmt.Errorf("error decoding import response: %v", err)
	}

	// Set the resource data
	if err := d.Set("kind", importedCert.Kind); err != nil {
		return nil, err
	}
	if err := d.Set("api_version", importedCert.APIVersion); err != nil {
		return nil, err
	}
	if err := d.Set("name", importedCert.Meta.Name); err != nil {
		return nil, err
	}
	if err := d.Set("certificate_data", importedCert.Spec.CertificateData); err != nil {
		return nil, err
	}
	if err := d.Set("description", importedCert.Spec.Description); err != nil {
		return nil, err
	}

	// Note: We don't set the private_key as it's sensitive and might not be returned by the API

	// The ID is already set by Terraform before calling this function

	return []*schema.ResourceData{d}, nil
}
