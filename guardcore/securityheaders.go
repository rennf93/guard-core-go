package guardcore

import (
	"fmt"
	"log"
	"regexp"
	"strings"
)

// Security headers management, ported from the reference
// guard_core/handlers/security_headers_handler.py plus its config and
// validation mixins (_security_headers_config.py) and the field defaults in
// guard_core/_security_config_fields.py (security_headers). The engine owns
// the logic (responseHeaders); adapters apply the map to their responses.

// HSTSConfig mirrors the security_headers "hsts" block
// ({"max_age": int, "include_subdomains": bool, "preload": bool}). A nil
// HSTS means no Strict-Transport-Security header, exactly like the
// reference's hsts_config=None when max_age is absent.
type HSTSConfig struct {
	MaxAge            int
	IncludeSubdomains bool
	Preload           bool
}

// CSPDirective is one Content-Security-Policy directive with its sources.
// The reference stores CSP as an insertion-ordered dict of directive ->
// source list; the slice keeps the built header deterministic.
type CSPDirective struct {
	Name    string
	Sources []string
}

// SecurityHeadersConfig mirrors the reference security_headers dict keys:
// enabled, hsts, csp, frame_options, content_type_options, xss_protection,
// referrer_policy, permissions_policy and custom.
//
// An empty string in FrameOptions/ContentTypeOptions/XSSProtection/
// ReferrerPolicy keeps the class default header (the reference dict lookup
// returning None). PermissionsPolicy carries pointer semantics to reproduce
// the reference three-way value: nil keeps the class default, a pointer to
// "" removes the header (a falsy configured value), any other value
// overrides it.
type SecurityHeadersConfig struct {
	Enabled            bool
	HSTS               *HSTSConfig
	CSP                []CSPDirective
	FrameOptions       string
	ContentTypeOptions string
	XSSProtection      string
	ReferrerPolicy     string
	PermissionsPolicy  *string
	Custom             map[string]string
}

// DefaultSecurityHeaders returns the reference's default security_headers
// block (guard_core/_security_config_fields.py:328-345).
func DefaultSecurityHeaders() *SecurityHeadersConfig {
	permissionsPolicy := "geolocation=(), microphone=(), camera=()"
	return &SecurityHeadersConfig{
		Enabled: true,
		HSTS: &HSTSConfig{
			MaxAge:            31536000,
			IncludeSubdomains: true,
			Preload:           false,
		},
		CSP:                nil,
		FrameOptions:       "SAMEORIGIN",
		ContentTypeOptions: "nosniff",
		XSSProtection:      "1; mode=block",
		ReferrerPolicy:     "strict-origin-when-cross-origin",
		PermissionsPolicy:  &permissionsPolicy,
		Custom:             nil,
	}
}

// classDefaultHeaders mirrors SecurityHeadersManager.default_headers
// (security_headers_handler.py:32-43), in table order.
var classDefaultHeaders = [][2]string{
	{"X-Content-Type-Options", "nosniff"},
	{"X-Frame-Options", "SAMEORIGIN"},
	{"X-XSS-Protection", "1; mode=block"},
	{"Referrer-Policy", "strict-origin-when-cross-origin"},
	{"Permissions-Policy", "geolocation=(), microphone=(), camera=()"},
	{"X-Permitted-Cross-Domain-Policies", "none"},
	{"X-Download-Options", "noopen"},
	{"Cross-Origin-Embedder-Policy", "require-corp"},
	{"Cross-Origin-Opener-Policy", "same-origin"},
	{"Cross-Origin-Resource-Policy", "same-origin"},
}

var headerNameTokenRE = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)

const maxHeaderValueBytes = 8192

// validateHeaderName mirrors _validate_header_name: the value must be a
// non-empty RFC 7230 token.
func validateHeaderName(name string) (string, error) {
	if !headerNameTokenRE.MatchString(name) {
		return "", fmt.Errorf("invalid header name: %q", name)
	}
	return name, nil
}

// validateHeaderValue mirrors _validate_header_value: no CR/LF, at most
// 8192 bytes, control characters below 0x20 dropped except tab.
func validateHeaderValue(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("invalid header value contains newline: %q", value)
	}
	if len(value) > maxHeaderValueBytes {
		return "", fmt.Errorf("header value too long: %d bytes", len(value))
	}
	var b strings.Builder
	for _, r := range value {
		if r >= 32 || r == '\t' {
			b.WriteRune(r)
		}
	}
	return b.String(), nil
}

func overrideHeaderValue(value string) (string, error) {
	sanitized, err := validateHeaderValue(value)
	if err != nil {
		return "", err
	}
	return sanitized, nil
}

// buildCSP mirrors _build_csp: "directive source1 source2" joined with "; ",
// bare directives kept when they carry no sources.
func buildCSP(csp []CSPDirective) string {
	parts := make([]string, 0, len(csp))
	for _, directive := range csp {
		if len(directive.Sources) > 0 {
			parts = append(parts, directive.Name+" "+strings.Join(directive.Sources, " "))
			continue
		}
		parts = append(parts, directive.Name)
	}
	return strings.Join(parts, "; ")
}

// buildHSTS mirrors _build_hsts plus the _compute_hsts_config preload
// corrections: preload requires max_age >= 31536000 and includeSubDomains.
func buildHSTS(hsts *HSTSConfig) string {
	if hsts == nil {
		return ""
	}
	preload := hsts.Preload
	includeSubdomains := hsts.IncludeSubdomains
	if preload {
		if hsts.MaxAge < 31536000 {
			log.Printf("HSTS preload requires max_age >= 31536000")
			preload = false
		}
		if !includeSubdomains {
			log.Printf("HSTS preload requires includeSubDomains")
			includeSubdomains = true
		}
	}
	parts := []string{fmt.Sprintf("max-age=%d", hsts.MaxAge)}
	if includeSubdomains {
		parts = append(parts, "includeSubDomains")
	}
	if preload {
		parts = append(parts, "preload")
	}
	return strings.Join(parts, "; ")
}

// responseHeaders computes the security header map for a config, mirroring
// SecurityHeadersManager.get_headers resolved against the reference
// security_headers dict: disabled or absent configuration yields no headers,
// the class defaults apply, the CSP and HSTS blocks extend them, and the
// custom headers land last (overriding everything).
func responseHeaders(cfg *SecurityConfig) map[string]string {
	headers := map[string]string{}
	if cfg == nil || cfg.SecurityHeaders == nil || !cfg.SecurityHeaders.Enabled {
		return headers
	}
	sh := cfg.SecurityHeaders
	for _, entry := range classDefaultHeaders {
		headers[entry[0]] = entry[1]
	}
	if sh.FrameOptions != "" {
		headers["X-Frame-Options"] = sh.FrameOptions
	}
	if sh.ContentTypeOptions != "" {
		headers["X-Content-Type-Options"] = sh.ContentTypeOptions
	}
	if sh.XSSProtection != "" {
		headers["X-XSS-Protection"] = sh.XSSProtection
	}
	if sh.ReferrerPolicy != "" {
		headers["Referrer-Policy"] = sh.ReferrerPolicy
	}
	if sh.PermissionsPolicy != nil {
		if *sh.PermissionsPolicy == "" {
			delete(headers, "Permissions-Policy")
		} else {
			headers["Permissions-Policy"] = *sh.PermissionsPolicy
		}
	}
	if csp := buildCSP(sh.CSP); csp != "" {
		headers["Content-Security-Policy"] = csp
	}
	if hsts := buildHSTS(sh.HSTS); hsts != "" {
		headers["Strict-Transport-Security"] = hsts
	}
	for name, value := range sh.Custom {
		headers[name] = value
	}
	return headers
}

// validateSecurityHeaders fail-closes the configured headers at config
// construction, mirroring the reference where _validate_header_name /
// _validate_header_value raise out of configure(). Values are sanitized in
// place so the built headers carry exactly the validated bytes.
func validateSecurityHeaders(sh *SecurityHeadersConfig) error {
	if sh == nil {
		return nil
	}
	type override struct {
		name    string
		current *string
	}
	overrides := []override{
		{"X-Frame-Options", &sh.FrameOptions},
		{"X-Content-Type-Options", &sh.ContentTypeOptions},
		{"X-XSS-Protection", &sh.XSSProtection},
		{"Referrer-Policy", &sh.ReferrerPolicy},
	}
	for _, entry := range overrides {
		if *entry.current == "" {
			continue
		}
		sanitized, err := overrideHeaderValue(*entry.current)
		if err != nil {
			return fmt.Errorf("security_headers[%s]: %w", entry.name, err)
		}
		*entry.current = sanitized
	}
	if sh.PermissionsPolicy != nil && *sh.PermissionsPolicy != "" {
		sanitized, err := overrideHeaderValue(*sh.PermissionsPolicy)
		if err != nil {
			return fmt.Errorf("security_headers[Permissions-Policy]: %w", err)
		}
		*sh.PermissionsPolicy = sanitized
	}
	for name, value := range sh.Custom {
		if _, err := validateHeaderName(name); err != nil {
			return fmt.Errorf("security_headers[custom]: %w", err)
		}
		sanitized, err := validateHeaderValue(value)
		if err != nil {
			return fmt.Errorf("security_headers[custom]: %w", err)
		}
		sh.Custom[name] = sanitized
	}
	return nil
}
