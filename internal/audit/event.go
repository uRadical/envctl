package audit

import (
	"time"
)

// Event represents an audit log entry
type Event struct {
	Timestamp time.Time      `json:"ts"`
	Level     string         `json:"level"`
	Category  string         `json:"category"`
	Action    string         `json:"action"`
	Message   string         `json:"msg"`
	Actor     string         `json:"actor,omitempty"`   // Fingerprint of who did it
	Project   string         `json:"project,omitempty"` // Project name
	Env       string         `json:"env,omitempty"`     // Environment name
	Target    string         `json:"target,omitempty"`  // For member actions
	Peer      string         `json:"peer,omitempty"`    // For peer actions
	Details   map[string]any `json:"details,omitempty"` // Additional context
	Success   bool           `json:"success"`
	Error     string         `json:"error,omitempty"`
}

// Log levels
const (
	LevelDebug = "DEBUG"
	LevelInfo  = "INFO"
	LevelWarn  = "WARN"
	LevelError = "ERROR"
)

// Action constants organized by category
const (
	// Identity actions
	ActionIdentityCreated   = "identity.created"
	ActionIdentityUnlocked  = "identity.unlocked"
	ActionIdentityLocked    = "identity.locked"
	ActionIdentityExported  = "identity.exported"
	ActionIdentityRecovered = "identity.recovered"
	ActionIdentityMigrated  = "identity.migrated"

	// Project actions
	ActionProjectCreated   = "project.created"
	ActionProjectDeleted   = "project.deleted"
	ActionProjectDissolved = "project.dissolved"
	ActionProjectJoined    = "project.joined"
	ActionProjectLeft      = "project.left"

	// Member actions
	ActionMemberInvited       = "member.invited"
	ActionMemberJoined        = "member.joined"
	ActionMemberRemoved       = "member.removed"
	ActionMemberRoleChanged   = "member.role_changed"
	ActionMemberAccessGranted = "member.access_granted"
	ActionMemberAccessRevoked = "member.access_revoked"

	// Secrets actions
	ActionSecretsRequested = "secrets.requested"
	ActionSecretsSent      = "secrets.sent"
	ActionSecretsReceived  = "secrets.received"
	ActionSecretsRotated   = "secrets.rotated"
	ActionSecretsUnlocked  = "secrets.unlocked"
	ActionSecretsLocked    = "secrets.locked"

	// Env actions
	ActionEnvAdded    = "env.added"
	ActionEnvRemoved  = "env.removed"
	ActionEnvUnlocked = "env.unlocked"
	ActionEnvLocked   = "env.locked"

	// Peer actions
	ActionPeerConnected    = "peer.connected"
	ActionPeerDisconnected = "peer.disconnected"
	ActionPeerVerified     = "peer.verified"
	ActionPeerRejected     = "peer.rejected"

	// Chain actions
	ActionChainSynced     = "chain.synced"
	ActionChainBlockAdded = "chain.block_added"
	ActionChainConflict   = "chain.conflict"
	ActionChainRepaired   = "chain.repaired"

	// Daemon actions
	ActionDaemonStarted = "daemon.started"
	ActionDaemonStopped = "daemon.stopped"
	ActionDaemonError   = "daemon.error"
)

// Categories for filtering
const (
	CategoryIdentity = "identity"
	CategoryProject  = "project"
	CategoryMember   = "member"
	CategorySecrets  = "secrets"
	CategoryEnv      = "env"
	CategoryPeer     = "peer"
	CategoryChain    = "chain"
	CategoryDaemon   = "daemon"
)

// AllCategories returns all valid categories
func AllCategories() []string {
	return []string{
		CategoryIdentity,
		CategoryProject,
		CategoryMember,
		CategorySecrets,
		CategoryEnv,
		CategoryPeer,
		CategoryChain,
		CategoryDaemon,
	}
}
