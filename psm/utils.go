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
