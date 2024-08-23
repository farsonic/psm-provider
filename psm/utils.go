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

func expandMeta(metaData map[string]interface{}) TunnelMeta {
	return TunnelMeta{
		Name:        getStringOrEmpty(metaData, "name"),
		Tenant:      getStringOrEmpty(metaData, "tenant"),
		Namespace:   getStringOrEmpty(metaData, "namespace"),
		DisplayName: getStringOrEmpty(metaData, "display_name"),
	}
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

func flattenMeta(meta *TunnelMeta) []interface{} {
	m := map[string]interface{}{
		"name":         meta.Name,
		"tenant":       meta.Tenant,
		"namespace":    meta.Namespace,
		"display_name": meta.DisplayName,
	}
	return []interface{}{m}
}

func flattenSpec(spec *TunnelSpec) []interface{} {
	tunnel := map[string]interface{}{
		"ha_mode":                     spec.HAMode,
		"tunnel_endpoints":            flattenTunnelEndpoints(spec.TunnelEndpoints),
		"policy_distribution_targets": spec.PolicyDistributionTargets,
		"disable_tcp_mss_adjust":      spec.DisableTCPMSSAdjust,
	}

	if spec.Config != nil {
		tunnel["lifetime"] = []interface{}{
			map[string]interface{}{
				"sa_lifetime":  spec.Config.SALifetime,
				"ike_lifetime": spec.Config.IKELifetime,
			},
		}
	}

	return []interface{}{tunnel}
}

func expandConfig(configData map[string]interface{}) *TunnelConfig {
	return &TunnelConfig{
		SALifetime:  getStringOrEmpty(configData, "sa_lifetime"),
		IKELifetime: getStringOrEmpty(configData, "ike_lifetime"),
	}
}

func flattenConfig(config *TunnelConfig) []interface{} {
	return []interface{}{
		map[string]interface{}{
			"sa_lifetime":  config.SALifetime,
			"ike_lifetime": config.IKELifetime,
		},
	}
}

func flattenTunnelEndpoints(endpoints []TunnelEndpoint) []interface{} {
	var result []interface{}
	for _, endpoint := range endpoints {
		e := map[string]interface{}{
			"interface_name":    endpoint.InterfaceName,
			"dse":               endpoint.DSE,
			"ike_version":       endpoint.IKEVersion,
			"ike_sa":            flattenIKESA(endpoint.IKESA),
			"ipsec_sa":          flattenIPSECSA(endpoint.IPSECSA),
			"local_identifier":  flattenIdentifier(endpoint.LocalIdentifier),
			"remote_identifier": flattenIdentifier(endpoint.RemoteIdentifier),
		}
		result = append(result, e)
	}
	return result
}

func flattenIKESA(ikesa *IKESA) []interface{} {
	if ikesa == nil {
		return nil
	}
	m := map[string]interface{}{
		"encryption_algorithms": ikesa.EncryptionAlgorithms,
		"hash_algorithms":       ikesa.HashAlgorithms,
		"dh_groups":             ikesa.DHGroups,
		"rekey_lifetime":        ikesa.RekeyLifetime,
		"reauth_lifetime":       ikesa.ReauthLifetime,
		"dpd_delay":             ikesa.DPDDelay,
		"ikev1_dpd_timeout":     ikesa.IKEV1DPDTimeout,
		"ike_initiator":         ikesa.IKEInitiator,
		"auth_type":             ikesa.AuthType,
	}

	if ikesa.PreSharedKey != "" {
		m["pre_shared_key"] = ikesa.PreSharedKey
	}

	if ikesa.AuthType == "certificates" {
		m["local_identity_certificates"] = ikesa.LocalIdentityCertificates
		m["remote_ca_certificates"] = ikesa.RemoteCACertificates
	}

	return []interface{}{m}
}

func flattenIPSECSA(ipsecsa *IPSECSA) []interface{} {
	if ipsecsa == nil {
		return nil
	}
	return []interface{}{map[string]interface{}{
		"encryption_algorithms": ipsecsa.EncryptionAlgorithms,
		"dh_groups":             ipsecsa.DHGroups,
		"rekey_lifetime":        ipsecsa.RekeyLifetime,
	}}
}

func flattenIdentifier(identifier Identifier) []interface{} {
	return []interface{}{map[string]interface{}{
		"type":  identifier.Type,
		"value": identifier.Value,
	}}
}

func expandMetaForUpdate(metaData map[string]interface{}) TunnelMeta {
	meta := TunnelMeta{}
	if labels, ok := metaData["labels"].(map[string]interface{}); ok {
		meta.Labels = &labels
	}
	// Add other fields that should be updatable
	if name, ok := metaData["name"].(string); ok {
		meta.Name = name
	}
	if displayName, ok := metaData["display_name"].(string); ok {
		meta.DisplayName = displayName
	}
	return meta
}

func expandSpecForUpdate(specData map[string]interface{}) TunnelSpec {
	spec := TunnelSpec{
		HAMode:                    getStringOrEmpty(specData, "ha_mode"),
		TunnelEndpoints:           expandTunnelEndpoints(specData["tunnel_endpoints"].([]interface{})),
		PolicyDistributionTargets: convertToStringSlice(specData["policy_distribution_targets"].([]interface{})),
		DisableTCPMSSAdjust:       getBoolOrDefault(specData, "disable_tcp_mss_adjust", false),
	}

	if config, ok := specData["config"].(map[string]interface{}); ok {
		spec.Config = &TunnelConfig{
			SALifetime:  getStringOrEmpty(config, "sa-lifetime"),
			IKELifetime: getStringOrEmpty(config, "ike-lifetime"),
		}
	}

	return spec
}
