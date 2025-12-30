package project

import (
	"fmt"

	"uradical.io/go/envctl/internal/chain"
)

// Re-export chain roles for convenience
const (
	RoleLead   = chain.RoleAdmin  // Alias: lead = admin (full access, can manage members)
	RoleMember = chain.RoleMember // Read/write access to environments
	RoleReader = chain.RoleReader // Read-only access
)

// Role is an alias for chain.Role
type Role = chain.Role

// ParseRole parses a string into a Role, supporting both old and new names
func ParseRole(s string) (Role, error) {
	switch s {
	case "lead", "admin":
		return RoleLead, nil
	case "member":
		return RoleMember, nil
	case "reader":
		return RoleReader, nil
	default:
		return "", fmt.Errorf("invalid role: %s (must be lead, member, or reader)", s)
	}
}

// RoleDisplayName returns a user-friendly display name for the role
func RoleDisplayName(r Role) string {
	switch r {
	case RoleLead:
		return "lead"
	case RoleMember:
		return "member"
	case RoleReader:
		return "reader"
	default:
		return string(r)
	}
}

// RoleDescription returns a human-readable description of the role
func RoleDescription(r Role) string {
	switch r {
	case RoleLead:
		return "Full access - can manage members and environments"
	case RoleMember:
		return "Read/write access to secrets"
	case RoleReader:
		return "Read-only access to secrets"
	default:
		return "Unknown role"
	}
}

// AllRoles returns all valid roles in order of decreasing privilege
func AllRoles() []Role {
	return []Role{RoleLead, RoleMember, RoleReader}
}

// RoleLevel returns the numeric level of a role (higher = more permissions)
func RoleLevel(r Role) int {
	switch r {
	case RoleReader:
		return 0
	case RoleMember:
		return 1
	case RoleLead:
		return 2
	default:
		return -1
	}
}

// CanPromote returns true if the role can be promoted to a higher role
func CanPromote(from, to Role) bool {
	return RoleLevel(to) > RoleLevel(from)
}

// CanDemote returns true if the role can be demoted to a lower role
func CanDemote(from, to Role) bool {
	return RoleLevel(to) < RoleLevel(from)
}
