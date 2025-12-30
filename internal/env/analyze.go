package env

import (
	"regexp"
	"strings"
)

// SensitivityLevel indicates how sensitive a variable is
type SensitivityLevel int

const (
	SensitivityNone SensitivityLevel = iota
	SensitivityLow
	SensitivityMedium
	SensitivityHigh
)

// AnalyzedVariable contains analysis results for a variable
type AnalyzedVariable struct {
	*Variable
	Sensitive   bool             `json:"sensitive"`
	Level       SensitivityLevel `json:"level"`
	Reason      string           `json:"reason,omitempty"`
	Pattern     string           `json:"pattern,omitempty"`
	Recommended bool             `json:"recommended"` // Recommended to share
}

// AnalysisResult contains the full analysis of an env file
type AnalysisResult struct {
	Path       string              `json:"path"`
	Variables  []*AnalyzedVariable `json:"variables"`
	TotalCount int                 `json:"total_count"`
	SafeCount  int                 `json:"safe_count"`
	Warnings   []string            `json:"warnings,omitempty"`
}

// Value patterns that indicate secrets
var valuePatterns = []struct {
	name    string
	pattern *regexp.Regexp
	level   SensitivityLevel
}{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), SensitivityHigh},
	{"AWS Secret Key", regexp.MustCompile(`[A-Za-z0-9/+=]{40}`), SensitivityHigh},
	{"Stripe Key", regexp.MustCompile(`sk_(live|test)_[a-zA-Z0-9]+`), SensitivityHigh},
	{"Stripe Publishable", regexp.MustCompile(`pk_(live|test)_[a-zA-Z0-9]+`), SensitivityLow},
	{"GitHub PAT", regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), SensitivityHigh},
	{"GitHub OAuth", regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`), SensitivityHigh},
	{"GitHub App", regexp.MustCompile(`(ghu|ghs)_[a-zA-Z0-9]{36}`), SensitivityHigh},
	{"GitLab Token", regexp.MustCompile(`glpat-[a-zA-Z0-9\-]{20}`), SensitivityHigh},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[a-zA-Z0-9-]+`), SensitivityHigh},
	{"Private Key Header", regexp.MustCompile(`-----BEGIN.*PRIVATE KEY-----`), SensitivityHigh},
	{"JWT", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`), SensitivityHigh},
	{"Base64 (long)", regexp.MustCompile(`^[a-zA-Z0-9+/]{40,}={0,2}$`), SensitivityMedium},
	{"Hex (long)", regexp.MustCompile(`^[a-fA-F0-9]{32,}$`), SensitivityMedium},
}

// Name patterns for sensitive variables (case-insensitive)
var namePatterns = []struct {
	pattern *regexp.Regexp
	level   SensitivityLevel
	reason  string
}{
	{regexp.MustCompile(`(?i)^(aws_)?secret`), SensitivityHigh, "secret in name"},
	{regexp.MustCompile(`(?i)password|passwd|pwd`), SensitivityHigh, "password in name"},
	{regexp.MustCompile(`(?i)private_?key`), SensitivityHigh, "private key"},
	{regexp.MustCompile(`(?i)api_?key`), SensitivityHigh, "API key"},
	{regexp.MustCompile(`(?i)api_?secret`), SensitivityHigh, "API secret"},
	{regexp.MustCompile(`(?i)auth_?token`), SensitivityHigh, "auth token"},
	{regexp.MustCompile(`(?i)access_?token`), SensitivityHigh, "access token"},
	{regexp.MustCompile(`(?i)refresh_?token`), SensitivityHigh, "refresh token"},
	{regexp.MustCompile(`(?i)bearer`), SensitivityHigh, "bearer token"},
	{regexp.MustCompile(`(?i)credential`), SensitivityHigh, "credential"},
	{regexp.MustCompile(`(?i)encryption_?key`), SensitivityHigh, "encryption key"},
	{regexp.MustCompile(`(?i)signing_?key`), SensitivityHigh, "signing key"},
	{regexp.MustCompile(`(?i)ssh_?key`), SensitivityHigh, "SSH key"},
	{regexp.MustCompile(`(?i)client_?secret`), SensitivityHigh, "client secret"},
	{regexp.MustCompile(`(?i)_token$`), SensitivityMedium, "token suffix"},
	{regexp.MustCompile(`(?i)_key$`), SensitivityMedium, "key suffix"},
}

// Exclusion patterns - these are NOT sensitive despite matching other patterns
var exclusionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)public`),
	regexp.MustCompile(`(?i)pubkey`),
	regexp.MustCompile(`(?i)public_?key`),
	regexp.MustCompile(`(?i)_id$`),
	regexp.MustCompile(`(?i)_name$`),
	regexp.MustCompile(`(?i)_url$`),
	regexp.MustCompile(`(?i)_host$`),
	regexp.MustCompile(`(?i)_port$`),
	regexp.MustCompile(`(?i)_path$`),
	regexp.MustCompile(`(?i)_dir$`),
	regexp.MustCompile(`(?i)_env$`),
	regexp.MustCompile(`(?i)_mode$`),
	regexp.MustCompile(`(?i)_level$`),
	regexp.MustCompile(`(?i)node_env`),
	regexp.MustCompile(`(?i)environment`),
	regexp.MustCompile(`(?i)debug`),
	regexp.MustCompile(`(?i)log_?level`),
}

// Analyze performs sensitivity analysis on an env file
func Analyze(envFile *EnvFile) *AnalysisResult {
	result := &AnalysisResult{
		Path:       envFile.Path,
		Variables:  make([]*AnalyzedVariable, 0, len(envFile.Variables)),
		TotalCount: len(envFile.Variables),
		Warnings:   make([]string, 0),
	}

	for _, v := range envFile.Variables {
		av := analyzeVariable(v)
		result.Variables = append(result.Variables, av)

		if !av.Sensitive {
			result.SafeCount++
		}
	}

	// Add warnings
	if len(envFile.Variables) == 0 {
		result.Warnings = append(result.Warnings, "No variables found in file")
	}

	sensitiveCount := result.TotalCount - result.SafeCount
	if sensitiveCount > 0 && float64(sensitiveCount)/float64(result.TotalCount) > 0.5 {
		result.Warnings = append(result.Warnings, "More than half of variables are sensitive")
	}

	return result
}

func analyzeVariable(v *Variable) *AnalyzedVariable {
	av := &AnalyzedVariable{
		Variable:    v,
		Sensitive:   false,
		Level:       SensitivityNone,
		Recommended: true,
	}

	// Check exclusion patterns first
	for _, p := range exclusionPatterns {
		if p.MatchString(v.Name) {
			return av // Not sensitive
		}
	}

	// Check name patterns
	for _, np := range namePatterns {
		if np.pattern.MatchString(v.Name) {
			av.Sensitive = true
			av.Level = np.level
			av.Reason = np.reason
			av.Recommended = false
			break
		}
	}

	// Check value patterns (only if not already marked as high sensitivity)
	if av.Level < SensitivityHigh && v.Value != "" {
		for _, vp := range valuePatterns {
			if vp.pattern.MatchString(v.Value) {
				av.Sensitive = true
				if vp.level > av.Level {
					av.Level = vp.level
				}
				av.Pattern = vp.name
				av.Recommended = false
				break
			}
		}
	}

	return av
}

// FilterSafe returns only non-sensitive variables
func (r *AnalysisResult) FilterSafe() []*AnalyzedVariable {
	result := make([]*AnalyzedVariable, 0)
	for _, v := range r.Variables {
		if !v.Sensitive {
			result = append(result, v)
		}
	}
	return result
}

// FilterSensitive returns only sensitive variables
func (r *AnalysisResult) FilterSensitive() []*AnalyzedVariable {
	result := make([]*AnalyzedVariable, 0)
	for _, v := range r.Variables {
		if v.Sensitive {
			result = append(result, v)
		}
	}
	return result
}

// FilterRecommended returns recommended variables
func (r *AnalysisResult) FilterRecommended() []*AnalyzedVariable {
	result := make([]*AnalyzedVariable, 0)
	for _, v := range r.Variables {
		if v.Recommended {
			result = append(result, v)
		}
	}
	return result
}

// SensitivityString returns a human-readable sensitivity level
func (l SensitivityLevel) String() string {
	switch l {
	case SensitivityNone:
		return "none"
	case SensitivityLow:
		return "low"
	case SensitivityMedium:
		return "medium"
	case SensitivityHigh:
		return "high"
	default:
		return "unknown"
	}
}

// MaskValue masks a sensitive value for display
func MaskValue(value string) string {
	if len(value) <= 4 {
		return strings.Repeat("*", len(value))
	}

	// Show first 4 and last 4 characters
	if len(value) <= 12 {
		return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
	}

	return value[:4] + "..." + value[len(value)-4:]
}
