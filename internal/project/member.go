package project

import (
	"time"

	"envctl.dev/go/envctl/internal/chain"
)

// Member wraps chain.Member with additional project-level methods
type Member = chain.Member

// MemberInfo provides a simplified view of a member
type MemberInfo struct {
	Name         string    `json:"name"`
	Fingerprint  string    `json:"fingerprint"`
	Role         string    `json:"role"`
	Environments []string  `json:"environments"`
	JoinedAt     time.Time `json:"joined_at"`
}

// ToMemberInfo converts a chain.Member to a MemberInfo
func ToMemberInfo(m *chain.Member, fingerprint string) MemberInfo {
	return MemberInfo{
		Name:         m.Name,
		Fingerprint:  fingerprint,
		Role:         RoleDisplayName(m.Role),
		Environments: m.Environments,
		JoinedAt:     m.JoinedAt,
	}
}

// CanChangeRoleTo returns true if a member's role can be changed to the new role
func CanChangeRoleTo(current, newRole Role) bool {
	if !current.Valid() || !newRole.Valid() {
		return false
	}
	return current != newRole
}

// IsLead returns true if the member has the lead/admin role
func IsLead(m *chain.Member) bool {
	return m.Role == RoleLead
}

// IsMember returns true if the member has the member role
func IsMember(m *chain.Member) bool {
	return m.Role == RoleMember
}

// IsReader returns true if the member has the reader role
func IsReader(m *chain.Member) bool {
	return m.Role == RoleReader
}
