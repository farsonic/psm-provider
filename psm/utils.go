package psm

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// convertToStringSlice converts various input types to a slice of strings
func convertToStringSlice(input interface{}) []string {
	var result []string
	inputSlice, ok := input.([]interface{})
	if !ok {
		return result
	}
	for _, v := range inputSlice {
		str, ok := v.(string)
		if !ok {
			continue
		}
		result = append(result, str)
	}
	return result
}

func getStringOrEmpty(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func getBoolOrDefault(m map[string]interface{}, key string, defaultValue bool) bool {
	if v, ok := m[key]; ok {
		b, ok := v.(bool)
		if ok {
			return b
		}
	}
	return defaultValue
}

func getStringSlice(m map[string]interface{}, key string) []string {
	if v, ok := m[key]; ok {
		if slice, ok := v.([]interface{}); ok {
			result := make([]string, len(slice))
			for i, item := range slice {
				result[i] = fmt.Sprintf("%v", item)
			}
			return result
		}
	}
	return nil
}

func expandStringList(list []interface{}) []string {
	result := make([]string, len(list))
	for i, v := range list {
		result[i] = v.(string)
	}
	return result
}

func ExpandStringSet(set *schema.Set) []string {
	list := set.List()
	result := make([]string, len(list))
	for i, v := range list {
		result[i] = v.(string)
	}
	return result
}

func FlattenStringList(list []string) *schema.Set {
	set := schema.NewSet(schema.HashString, []interface{}{})
	for _, v := range list {
		set.Add(v)
	}
	return set
}

func expandSpec(d *schema.ResourceData) TunnelSpec {
	tunnelData := d.Get("tunnel").([]interface{})[0].(map[string]interface{})

	spec := TunnelSpec{
		HAMode:                    getStringOrEmpty(tunnelData, "ha_mode"),
		TunnelEndpoints:           expandTunnelEndpoints(tunnelData["tunnel_endpoints"].([]interface{})),
		PolicyDistributionTargets: convertToStringSlice(tunnelData["policy_distribution_targets"].([]interface{})),
		DisableTCPMSSAdjust:       getBoolOrDefault(tunnelData, "disable_tcp_mss_adjust", false),
	}

	if lifetime, ok := tunnelData["lifetime"].([]interface{}); ok && len(lifetime) > 0 {
		lifetimeData := lifetime[0].(map[string]interface{})
		spec.Config = &TunnelConfig{
			SALifetime:  getStringOrEmpty(lifetimeData, "sa_lifetime"),
			IKELifetime: getStringOrEmpty(lifetimeData, "ike_lifetime"),
		}
	}

	return spec
}

func expandTunnelEndpoints(endpoints []interface{}) []TunnelEndpoint {
	result := make([]TunnelEndpoint, len(endpoints))
	for i, endpoint := range endpoints {
		endpointData := endpoint.(map[string]interface{})
		result[i] = TunnelEndpoint{
			InterfaceName:    getStringOrEmpty(endpointData, "interface_name"),
			DSE:              getStringOrEmpty(endpointData, "dse"),
			IKEVersion:       getStringOrEmpty(endpointData, "ike_version"),
			IKESA:            expandIKESA(endpointData["ike_sa"].([]interface{})[0].(map[string]interface{})),
			IPSECSA:          expandIPSECSA(endpointData["ipsec_sa"].([]interface{})[0].(map[string]interface{})),
			LocalIdentifier:  expandIdentifier(endpointData["local_identifier"].([]interface{})[0].(map[string]interface{})),
			RemoteIdentifier: expandIdentifier(endpointData["remote_identifier"].([]interface{})[0].(map[string]interface{})),
		}
	}
	return result
}

func expandIKESA(data map[string]interface{}) *IKESA {
	ikesa := &IKESA{
		EncryptionAlgorithms: convertToStringSlice(data["encryption_algorithms"].([]interface{})),
		HashAlgorithms:       convertToStringSlice(data["hash_algorithms"].([]interface{})),
		DHGroups:             convertToStringSlice(data["dh_groups"].([]interface{})),
		RekeyLifetime:        getStringOrEmpty(data, "rekey_lifetime"),
		PreSharedKey:         getStringOrEmpty(data, "pre_shared_key"),
		ReauthLifetime:       getStringOrEmpty(data, "reauth_lifetime"),
		DPDDelay:             getStringOrEmpty(data, "dpd_delay"),
		IKEV1DPDTimeout:      getStringOrEmpty(data, "ikev1_dpd_timeout"),
		IKEInitiator:         getBoolOrDefault(data, "ike_initiator", true),
		AuthType:             getStringOrEmpty(data, "auth_type"),
	}

	if ikesa.AuthType == "certificates" {
		ikesa.LocalIdentityCertificates = getStringOrEmpty(data, "local_identity_certificates")
		if certs, ok := data["remote_ca_certificates"].([]interface{}); ok {
			ikesa.RemoteCACertificates = convertToStringSlice(certs)
		}
	}

	return ikesa
}

func expandIPSECSA(data map[string]interface{}) *IPSECSA {
	return &IPSECSA{
		EncryptionAlgorithms: convertToStringSlice(data["encryption_algorithms"].([]interface{})),
		DHGroups:             convertToStringSlice(data["dh_groups"].([]interface{})),
		RekeyLifetime:        getStringOrEmpty(data, "rekey_lifetime"),
	}
}

func expandIdentifier(data map[string]interface{}) Identifier {
	return Identifier{
		Type:  getStringOrEmpty(data, "type"),
		Value: getStringOrEmpty(data, "value"),
	}
}

func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func flattenSpec(spec *TunnelSpec, d *schema.ResourceData) []interface{} {
	m := make(map[string]interface{})

	m["ha_mode"] = spec.HAMode
	m["policy_distribution_targets"] = spec.PolicyDistributionTargets
	m["disable_tcp_mss_adjust"] = spec.DisableTCPMSSAdjust

	// Only include lifetime if it exists in the current state
	if v, ok := d.GetOk("tunnel.0.lifetime"); ok {
		m["lifetime"] = v.([]interface{})
	}

	tunnelEndpoints := make([]interface{}, len(spec.TunnelEndpoints))
	for i, endpoint := range spec.TunnelEndpoints {
		endpointMap := make(map[string]interface{})
		endpointMap["interface_name"] = endpoint.InterfaceName
		endpointMap["dse"] = endpoint.DSE
		endpointMap["ike_version"] = endpoint.IKEVersion

		if endpoint.IKESA != nil {
			ikesa := make(map[string]interface{})
			ikesa["encryption_algorithms"] = endpoint.IKESA.EncryptionAlgorithms
			ikesa["hash_algorithms"] = endpoint.IKESA.HashAlgorithms
			ikesa["dh_groups"] = endpoint.IKESA.DHGroups
			ikesa["rekey_lifetime"] = endpoint.IKESA.RekeyLifetime
			ikesa["reauth_lifetime"] = endpoint.IKESA.ReauthLifetime
			ikesa["dpd_delay"] = endpoint.IKESA.DPDDelay
			ikesa["ikev1_dpd_timeout"] = endpoint.IKESA.IKEV1DPDTimeout
			ikesa["ike_initiator"] = endpoint.IKESA.IKEInitiator
			ikesa["auth_type"] = endpoint.IKESA.AuthType
			if endpoint.IKESA.LocalIdentityCertificates != "" {
				ikesa["local_identity_certificates"] = endpoint.IKESA.LocalIdentityCertificates
			}
			if len(endpoint.IKESA.RemoteCACertificates) > 0 {
				ikesa["remote_ca_certificates"] = endpoint.IKESA.RemoteCACertificates
			}

			// Preserve pre_shared_key if it exists in the current state
			if v, ok := d.GetOk(fmt.Sprintf("tunnel.0.tunnel_endpoints.%d.ike_sa.0.pre_shared_key", i)); ok {
				ikesa["pre_shared_key"] = v.(string)
			}

			endpointMap["ike_sa"] = []interface{}{ikesa}
		}

		if endpoint.IPSECSA != nil {
			ipsecsa := make(map[string]interface{})
			ipsecsa["encryption_algorithms"] = endpoint.IPSECSA.EncryptionAlgorithms
			ipsecsa["dh_groups"] = endpoint.IPSECSA.DHGroups
			ipsecsa["rekey_lifetime"] = endpoint.IPSECSA.RekeyLifetime
			endpointMap["ipsec_sa"] = []interface{}{ipsecsa}
		}

		endpointMap["local_identifier"] = []interface{}{
			map[string]interface{}{
				"type":  endpoint.LocalIdentifier.Type,
				"value": endpoint.LocalIdentifier.Value,
			},
		}

		endpointMap["remote_identifier"] = []interface{}{
			map[string]interface{}{
				"type":  endpoint.RemoteIdentifier.Type,
				"value": endpoint.RemoteIdentifier.Value,
			},
		}

		tunnelEndpoints[i] = endpointMap
	}

	m["tunnel_endpoints"] = tunnelEndpoints

	return []interface{}{m}
}
