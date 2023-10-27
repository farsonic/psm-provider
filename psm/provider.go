package psm

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type FabricName string
type SwitchName string

func Provider() *schema.Provider {
	return &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			"psm_network":      resourceNetwork(),
			"psm_workload":     resourceWorkload(),
			"psm_rules":        resourceRules(),
			"psm_vrf":          resourceVRF(),
			"psm_ipcollection": resourceIPCollection(),
		},
		Schema: map[string]*schema.Schema{
			"user": &schema.Schema{
				Description: "The username for the PSM Server",
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("API_USER", nil),
			},
			"password": &schema.Schema{
				Description: "The users password for the PSM Server",
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("API_PASSWORD", nil),
			},
			"server": &schema.Schema{
				Description: "The PSM server IP address or URL",
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("API_SERVER", nil),
			},
			"insecure": &schema.Schema{
				Description: "Skip SSL certificate verification.",
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
			},
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	//... existing logic
	config := &Config{
		User:     d.Get("user").(string),
		Password: d.Get("password").(string),
		Server:   d.Get("server").(string),
		Insecure: d.Get("insecure").(bool),
	}

	err := config.Authenticate()
	if err != nil {
		return nil, diag.FromErr(err)
	}
	return config, nil
}
