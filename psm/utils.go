package psm

// convertToStringSlice converts various input types to a slice of strings
func convertToStringSlice(input interface{}) []string {
	var result []string
	inputSlice, ok := input.([]interface{})
	if !ok {
		// handle the error accordingly
		return result
	}
	for _, v := range inputSlice {
		str, ok := v.(string)
		if !ok {
			// handle the error accordingly
			continue
		}
		result = append(result, str)
	}
	return result
}
