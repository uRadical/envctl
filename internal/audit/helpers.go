package audit

import "time"

// Info logs an info-level event
func Info(action, message string, fields ...any) {
	event := Event{
		Level:   LevelInfo,
		Action:  action,
		Message: message,
		Success: true,
	}
	applyFields(&event, fields)
	Default().Log(event)
}

// Debug logs a debug-level event
func Debug(action, message string, fields ...any) {
	event := Event{
		Level:   LevelDebug,
		Action:  action,
		Message: message,
		Success: true,
	}
	applyFields(&event, fields)
	Default().Log(event)
}

// Warn logs a warning-level event
func Warn(action, message string, fields ...any) {
	event := Event{
		Level:   LevelWarn,
		Action:  action,
		Message: message,
		Success: true,
	}
	applyFields(&event, fields)
	Default().Log(event)
}

// Error logs an error-level event
func Error(action, message string, err error, fields ...any) {
	event := Event{
		Level:   LevelError,
		Action:  action,
		Message: message,
		Success: false,
	}
	if err != nil {
		event.Error = err.Error()
	}
	applyFields(&event, fields)
	Default().Log(event)
}

// LogEvent logs a full event structure
func LogEvent(event Event) {
	Default().Log(event)
}

// applyFields applies key-value fields to an event
func applyFields(event *Event, fields []any) {
	for i := 0; i < len(fields)-1; i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			continue
		}
		value := fields[i+1]

		switch key {
		case "project":
			event.Project, _ = value.(string)
		case "env":
			event.Env, _ = value.(string)
		case "target":
			event.Target, _ = value.(string)
		case "peer":
			event.Peer, _ = value.(string)
		case "actor":
			event.Actor, _ = value.(string)
		case "category":
			event.Category, _ = value.(string)
		default:
			if event.Details == nil {
				event.Details = make(map[string]any)
			}
			event.Details[key] = value
		}
	}
}

// Convenience functions for common events

// LogIdentityCreated logs identity creation
func LogIdentityCreated(name, fingerprint string) {
	Info(ActionIdentityCreated, "identity created",
		"target", name,
		"fingerprint", fingerprint,
	)
}

// LogIdentityUnlocked logs identity unlock
func LogIdentityUnlocked(name string) {
	Info(ActionIdentityUnlocked, "identity unlocked",
		"target", name,
	)
}

// LogIdentityMigrated logs identity migration to YubiKey
func LogIdentityMigrated(name string, serial uint32) {
	Info(ActionIdentityMigrated, "identity migrated to YubiKey",
		"target", name,
		"yubikey_serial", serial,
	)
}

// LogProjectCreated logs project creation
func LogProjectCreated(project string) {
	Info(ActionProjectCreated, "project created",
		"project", project,
	)
}

// LogProjectJoined logs joining a project
func LogProjectJoined(project string) {
	Info(ActionProjectJoined, "joined project",
		"project", project,
	)
}

// LogMemberInvited logs member invitation
func LogMemberInvited(project, member string) {
	Info(ActionMemberInvited, "member invited",
		"project", project,
		"target", member,
	)
}

// LogSecretsSent logs secrets being sent
func LogSecretsSent(project, env, target string, varCount int) {
	Info(ActionSecretsSent, "secrets sent",
		"project", project,
		"env", env,
		"target", target,
		"variables", varCount,
	)
}

// LogSecretsReceived logs secrets being received
func LogSecretsReceived(project, env, from string, varCount int) {
	Info(ActionSecretsReceived, "secrets received",
		"project", project,
		"env", env,
		"peer", from,
		"variables", varCount,
	)
}

// LogSecretsRotated logs secrets rotation
func LogSecretsRotated(project, env string, changes int) {
	Info(ActionSecretsRotated, "secrets rotated",
		"project", project,
		"env", env,
		"changes", changes,
	)
}

// LogEnvUnlocked logs environment unlock
func LogEnvUnlocked(project, env string) {
	Info(ActionEnvUnlocked, "environment unlocked",
		"project", project,
		"env", env,
	)
}

// LogPeerConnected logs peer connection
func LogPeerConnected(peer, addr string) {
	Info(ActionPeerConnected, "peer connected",
		"peer", peer,
		"addr", addr,
	)
}

// LogPeerDisconnected logs peer disconnection
func LogPeerDisconnected(peer, reason string) {
	Info(ActionPeerDisconnected, "peer disconnected",
		"peer", peer,
		"reason", reason,
	)
}

// LogPeerVerified logs peer verification
func LogPeerVerified(peer, method string) {
	Info(ActionPeerVerified, "peer verified",
		"peer", peer,
		"method", method,
	)
}

// LogChainSynced logs chain sync
func LogChainSynced(project string, blocks int) {
	Info(ActionChainSynced, "chain synced",
		"project", project,
		"blocks", blocks,
	)
}

// LogDaemonStarted logs daemon start
func LogDaemonStarted(version string, port int) {
	Info(ActionDaemonStarted, "daemon started",
		"version", version,
		"port", port,
	)
}

// LogDaemonStopped logs daemon stop
func LogDaemonStopped(reason string) {
	Info(ActionDaemonStopped, "daemon stopped",
		"reason", reason,
	)
}

// Query is a convenience function to query the default logger
func Query(opts QueryOpts) []Event {
	return Default().Query(opts)
}

// QuerySince returns events since the given duration ago
func QuerySince(d time.Duration, limit int) []Event {
	since := time.Now().Add(-d)
	return Query(QueryOpts{
		Since: &since,
		Limit: limit,
	})
}

// QueryByCategory returns events for a specific category
func QueryByCategory(category string, limit int) []Event {
	return Query(QueryOpts{
		Category: category,
		Limit:    limit,
	})
}

// QueryByProject returns events for a specific project
func QueryByProject(project string, limit int) []Event {
	return Query(QueryOpts{
		Project: project,
		Limit:   limit,
	})
}

// QueryErrors returns error-level events
func QueryErrors(limit int) []Event {
	return Query(QueryOpts{
		Level: LevelError,
		Limit: limit,
	})
}
