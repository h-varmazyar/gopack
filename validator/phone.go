package validator

import (
	"regexp"
	"strings"
)

func IsValidMobile(mobile string) bool {
	if mobile == "" {
		return false
	}

	// normalize: trim and remove common separators
	mobile = strings.TrimSpace(mobile)
	mobile = strings.ReplaceAll(mobile, " ", "")
	mobile = strings.ReplaceAll(mobile, "-", "")
	mobile = strings.ReplaceAll(mobile, "(", "")
	mobile = strings.ReplaceAll(mobile, ")", "")

	// Accept formats:
	//  - 09XXXXXXXXX (common local format, 11 digits)
	//  - +989XXXXXXXXX (with +98 country code)
	//  - 00989XXXXXXXXX (international without +)
	//  - 989XXXXXXXXX (country code without +)
	// Regex: optional prefix (+98 | 0098 | 98 | 0) followed by 9XXXXXXXXX
	re := regexp.MustCompile(`^(?:\+98|0098|98|0)?9\d{9}$`)
	return re.MatchString(mobile)
}
