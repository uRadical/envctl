package i18n

import (
	"fmt"
	"os"
	"strings"
)

var lang = "en"

var messages = map[string]map[string]string{
	"en": {
		// Daemon messages
		"daemon.not_running":     "Daemon not running. Start with: envctl daemon start",
		"daemon.started":         "Daemon started (PID %d)",
		"daemon.stopped":         "Daemon stopped",
		"daemon.already_running": "Daemon already running (PID %d)",
		"daemon.starting":        "Starting daemon...",
		"daemon.stopping":        "Stopping daemon...",

		// Identity messages
		"identity.created":    "Identity created: %s",
		"identity.passphrase": "Enter passphrase: ",
		"identity.confirm":    "Confirm passphrase: ",
		"identity.mismatch":   "Passphrases do not match",
		"identity.wrong":      "Wrong passphrase",
		"identity.not_found":  "No identity found. Run 'envctl init' first",

		// Team messages
		"team.created":        "Team '%s' created. You are the admin.",
		"team.joined":         "Joined team '%s'",
		"team.left":           "Left team '%s'",
		"team.not_found":      "Team not found: %s",
		"team.already_exists": "Team already exists: %s",
		"team.member_added":   "Member added to team",
		"team.member_removed": "Member removed from team",

		// Invite messages
		"team.invite.sent":      "Invite sent for %s",
		"team.invite.pending":   "Invite pending approval",
		"team.invite.approved":  "Invite approved",
		"team.invite.denied":    "Invite denied",
		"team.invite.expired":   "Invite expired",
		"team.invite.received":  "Received invite from %s for team %s",

		// Request messages
		"request.sent":     "Request sent to %d peers",
		"request.received": "%s is requesting your %s env",
		"request.approved": "Request approved, sent %d variables",
		"request.denied":   "Request denied",
		"request.expired":  "Request expired after %s",
		"request.pending":  "Request pending",

		// Environment messages
		"env.received":  "Received %s env from %s (%d variables)",
		"env.switched":  "Switched to %s",
		"env.stale":     "Your %s env may be outdated (updated by %s %s ago)",
		"env.not_found": "Environment not found: %s",
		"env.created":   "Environment created: %s",
		"env.deleted":   "Environment deleted: %s",

		// Chain messages
		"chain.valid":     "Chain valid (%d blocks)",
		"chain.corrupted": "Chain corrupted, attempting recovery...",
		"chain.recovered": "Chain recovered from backup",
		"chain.synced":    "Chain synced (%d new blocks)",

		// Peer messages
		"peer.connected":    "Connected to %s",
		"peer.disconnected": "Disconnected from %s",
		"peer.verified":     "Verified %s",
		"peer.not_found":    "Peer not found: %s",

		// Error messages
		"error.no_access":        "%s does not have access to %s",
		"error.not_in_team":      "%s is not a member of this team",
		"error.upgrade_required": "Peer requires newer version. Please upgrade.",
		"error.permission":       "Permission denied",
		"error.network":          "Network error: %s",
		"error.invalid_input":    "Invalid input: %s",

		// Approval messages
		"approval.required":  "Approval required (%d of %d)",
		"approval.received":  "Received approval from %s",
		"approval.complete":  "Approval complete",

		// General messages
		"confirm.yes":     "yes",
		"confirm.no":      "no",
		"confirm.default": "[Y/n]",
		"loading":         "Loading...",
		"done":            "Done",
		"cancelled":       "Cancelled",
	},
}

// T translates a message key with optional format arguments
func T(key string, args ...any) string {
	msg := messages[lang][key]
	if msg == "" {
		msg = messages["en"][key]
	}
	if msg == "" {
		return key
	}
	if len(args) > 0 {
		return fmt.Sprintf(msg, args...)
	}
	return msg
}

// SetLang sets the current language
func SetLang(l string) {
	// Normalize language code
	l = strings.ToLower(strings.TrimSpace(l))
	if len(l) > 2 {
		l = l[:2]
	}

	if _, ok := messages[l]; ok {
		lang = l
	}
}

// GetLang returns the current language
func GetLang() string {
	return lang
}

// DetectLang detects the user's preferred language from environment
func DetectLang() string {
	// Check ENVCTL_LANG first
	if l := os.Getenv("ENVCTL_LANG"); l != "" {
		return normalizeLocale(l)
	}

	// Check LC_MESSAGES
	if l := os.Getenv("LC_MESSAGES"); l != "" {
		return normalizeLocale(l)
	}

	// Check LANG
	if l := os.Getenv("LANG"); l != "" {
		return normalizeLocale(l)
	}

	// Check LC_ALL
	if l := os.Getenv("LC_ALL"); l != "" {
		return normalizeLocale(l)
	}

	return "en"
}

// normalizeLocale extracts a 2-letter language code from a locale string
func normalizeLocale(locale string) string {
	// Remove encoding (e.g., "en_US.UTF-8" -> "en_US")
	if idx := strings.Index(locale, "."); idx > 0 {
		locale = locale[:idx]
	}

	// Remove country code (e.g., "en_US" -> "en")
	if idx := strings.Index(locale, "_"); idx > 0 {
		locale = locale[:idx]
	}

	// Normalize to lowercase
	locale = strings.ToLower(locale)

	if len(locale) >= 2 {
		return locale[:2]
	}

	return "en"
}

// Init initializes i18n with the detected or configured language
func Init(configuredLang string) {
	if configuredLang != "" {
		SetLang(configuredLang)
	} else {
		SetLang(DetectLang())
	}
}

// AvailableLanguages returns the list of available languages
func AvailableLanguages() []string {
	langs := make([]string, 0, len(messages))
	for l := range messages {
		langs = append(langs, l)
	}
	return langs
}

// AddMessages adds or updates messages for a language
func AddMessages(langCode string, msgs map[string]string) {
	if messages[langCode] == nil {
		messages[langCode] = make(map[string]string)
	}
	for k, v := range msgs {
		messages[langCode][k] = v
	}
}
