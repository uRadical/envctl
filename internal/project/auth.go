package project

import (
	"bytes"
	"fmt"

	"envctl.dev/go/envctl/internal/chain"
)

// AuthError represents an authorization error
type AuthError struct {
	Action      string
	Fingerprint string
	Role        Role
	Message     string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("authorization denied: %s (role=%s): %s",
		e.Action, RoleDisplayName(e.Role), e.Message)
}

// Authorizer handles authorization checks for project operations
type Authorizer struct {
	chain *chain.Chain
}

// NewAuthorizer creates a new authorizer for a chain
func NewAuthorizer(c *chain.Chain) *Authorizer {
	return &Authorizer{chain: c}
}

// GetMember returns the member with the given signing public key
func (a *Authorizer) GetMember(signingPub []byte) *chain.Member {
	return a.chain.Member(signingPub)
}

// GetMemberByName returns the member with the given name
func (a *Authorizer) GetMemberByName(name string) *chain.Member {
	return a.chain.FindMemberByName(name)
}

// IsMember returns true if the signing key belongs to a member
func (a *Authorizer) IsMember(signingPub []byte) bool {
	return a.chain.IsMember(signingPub)
}

// Authorize checks if the actor can perform the given action
func (a *Authorizer) Authorize(actorSigningPub []byte, action chain.Action) error {
	return a.chain.CanPropose(action, actorSigningPub)
}

// ValidateAddMember checks if the actor can add a new member with the given role
func (a *Authorizer) ValidateAddMember(actorSigningPub, targetSigningPub []byte, targetRole Role) error {
	// Check basic authorization
	if err := a.Authorize(actorSigningPub, chain.ActionAddMember); err != nil {
		return err
	}

	// Check if target is already a member
	if a.chain.IsMember(targetSigningPub) {
		return fmt.Errorf("user is already a member")
	}

	// Validate target role
	if !targetRole.Valid() {
		return fmt.Errorf("invalid role: %s", targetRole)
	}

	return nil
}

// ValidateRemoveMember checks if the actor can remove the target member
func (a *Authorizer) ValidateRemoveMember(actorSigningPub, targetSigningPub []byte) error {
	// Check basic authorization
	if err := a.Authorize(actorSigningPub, chain.ActionRemoveMember); err != nil {
		return err
	}

	// Check if target exists
	target := a.chain.Member(targetSigningPub)
	if target == nil {
		return fmt.Errorf("user is not a member")
	}

	// Cannot remove yourself (use leave instead)
	if bytes.Equal(actorSigningPub, targetSigningPub) {
		return fmt.Errorf("cannot remove yourself; use 'leave' instead")
	}

	// Count leads to prevent removing the last lead
	if target.Role == RoleLead {
		leadCount := a.CountLeads()
		if leadCount <= 1 {
			return fmt.Errorf("cannot remove the last lead from the project")
		}
	}

	return nil
}

// ValidateRoleChange checks if the actor can change the target's role
func (a *Authorizer) ValidateRoleChange(actorSigningPub, targetSigningPub []byte, newRole Role) error {
	// Check basic authorization
	if err := a.Authorize(actorSigningPub, chain.ActionChangeRole); err != nil {
		return err
	}

	// Check if target exists
	target := a.chain.Member(targetSigningPub)
	if target == nil {
		return fmt.Errorf("user is not a member")
	}

	// Validate new role
	if !newRole.Valid() {
		return fmt.Errorf("invalid role: %s", newRole)
	}

	// Check if role is actually changing
	if target.Role == newRole {
		return fmt.Errorf("user already has role %s", RoleDisplayName(newRole))
	}

	// If demoting from lead, ensure at least one lead remains
	if target.Role == RoleLead && newRole != RoleLead {
		leadCount := a.CountLeads()
		if leadCount <= 1 {
			return fmt.Errorf("cannot demote the last lead; promote another member first")
		}
	}

	return nil
}

// CountLeads returns the number of leads in the project
func (a *Authorizer) CountLeads() int {
	count := 0
	for _, m := range a.chain.Members() {
		if m.Role == RoleLead {
			count++
		}
	}
	return count
}

// GetLeads returns all lead members
func (a *Authorizer) GetLeads() []*chain.Member {
	var leads []*chain.Member
	for _, m := range a.chain.Members() {
		if m.Role == RoleLead {
			leads = append(leads, m)
		}
	}
	return leads
}
