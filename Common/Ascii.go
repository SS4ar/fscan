package Common

import "strings"

// sanitizeASCII normalizes whitespace and strips control characters.
// It keeps Unicode text (e.g., Russian UI strings) intact.
func sanitizeASCII(input string) string {
	if input == "" {
		return input
	}

	var builder strings.Builder
	builder.Grow(len(input))
	for _, r := range input {
		switch r {
		case '\n', '\r', '\t':
			builder.WriteByte(' ')
		default:
			if r < 32 || r == 127 {
				builder.WriteByte(' ')
				continue
			}
			builder.WriteRune(r)
		}
	}

	return strings.Join(strings.Fields(builder.String()), " ")
}

func sanitizeValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case string:
		return sanitizeASCII(typed)
	case []string:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, sanitizeASCII(item))
		}
		return out
	case []interface{}:
		out := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			out = append(out, sanitizeValue(item))
		}
		return out
	case map[string]interface{}:
		return sanitizeDetailsMap(typed)
	default:
		return value
	}
}

func sanitizeDetailsMap(details map[string]interface{}) map[string]interface{} {
	if details == nil {
		return nil
	}
	out := make(map[string]interface{}, len(details))
	for key, value := range details {
		out[sanitizeASCII(key)] = sanitizeValue(value)
	}
	return out
}

func sanitizeScanResult(result *ScanResult) *ScanResult {
	if result == nil {
		return nil
	}
	sanitized := *result
	sanitized.Type = ResultType(sanitizeASCII(string(result.Type)))
	sanitized.Target = sanitizeASCII(result.Target)
	sanitized.Status = sanitizeASCII(result.Status)
	sanitized.Details = sanitizeDetailsMap(result.Details)
	return &sanitized
}

