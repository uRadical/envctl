package chain

import (
	"bytes"
	"errors"
	"fmt"
	"math"
)

// RequiredApprovals calculates the number of approvals needed for a block
// Based on team size and policy
func (c *Chain) RequiredApprovals(block *Block) int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	memberCount := len(c.members)
	policy := c.policy

	// For self-removal, no approvals needed
	if block.Action == ActionLeaveTeam {
		return 0
	}

	// Adding environments requires no approval - any member can do it
	if block.Action == ActionAddEnv {
		return 0
	}

	// Invites don't require approval - only admins can create them
	if block.Action == ActionInvite {
		return 0
	}

	// Solo mode: single-admin teams operate without approvals
	// This must be explicitly enabled in policy - default is to require approvals
	if memberCount == 1 && policy.SoloMode {
		return 0
	}

	// Small team security: if there are other members, require at least 1 approval
	// This prevents admins from acting unilaterally in 2-3 person teams
	if memberCount > 1 && memberCount < 3 {
		return 1
	}

	// Calculate required approvals: max(min_approvals, ceil(team_size * threshold))
	thresholdApprovals := int(math.Ceil(float64(memberCount) * policy.ApprovalThreshold))
	required := policy.MinApprovals
	if thresholdApprovals > required {
		required = thresholdApprovals
	}

	// Don't require more approvals than available members minus proposer
	maxPossible := memberCount - 1
	if required > maxPossible {
		required = maxPossible
	}

	return required
}

// HasSufficientApprovals checks if a block has enough approvals
func (c *Chain) HasSufficientApprovals(block *Block) bool {
	required := c.RequiredApprovals(block)
	return c.CountValidApprovals(block) >= required
}

// CountValidApprovals counts valid approvals from current members
func (c *Chain) CountValidApprovals(block *Block) int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	count := 0
	for _, approval := range block.Approvals {
		// Check approver is a current member
		if !c.IsMemberLocked(approval.By) {
			continue
		}
		// Proposer cannot approve their own block
		if bytes.Equal(approval.By, block.ProposedBy) {
			continue
		}
		// Verify approval signature
		if !block.VerifyApproval(&approval) {
			continue
		}
		count++
	}
	return count
}

// CanApprove checks if a member can approve a block
func (c *Chain) CanApprove(block *Block, signingPub []byte) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check approver is a member
	member := c.members[string(signingPub)]
	if member == nil {
		return errors.New("approver is not a team member")
	}

	// Proposer cannot approve their own block
	if bytes.Equal(signingPub, block.ProposedBy) {
		return errors.New("cannot approve your own proposal")
	}

	// Check if already approved
	for _, approval := range block.Approvals {
		if bytes.Equal(approval.By, signingPub) {
			return errors.New("already approved this proposal")
		}
	}

	// For environment access changes, approver must have access to the environments
	if block.Action == ActionUpdateAccess {
		ac, err := block.GetAccessChange()
		if err != nil {
			return err
		}
		for _, env := range ac.Environments {
			if !c.hasEnvAccessLocked(signingPub, env) {
				return fmt.Errorf("approver does not have access to environment %s", env)
			}
		}
	}

	return nil
}

// CanPropose checks if a member can propose a specific action
func (c *Chain) CanPropose(action Action, signingPub []byte) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	member := c.members[string(signingPub)]
	if member == nil {
		return errors.New("proposer is not a team member")
	}

	switch action {
	case ActionAddMember, ActionRemoveMember, ActionChangeRole, ActionUpdatePolicy:
		if member.Role != RoleAdmin {
			return fmt.Errorf("action %s requires admin role", action)
		}

	case ActionInvite:
		// Only admins can create invites
		if member.Role != RoleAdmin {
			return fmt.Errorf("action %s requires admin role", action)
		}

	case ActionAddEnv:
		// Any member can add environments (no approval needed)

	case ActionRemoveEnv:
		// Only admins can remove environments
		if member.Role != RoleAdmin {
			return fmt.Errorf("action %s requires admin role", action)
		}

	case ActionUpdateAccess:
		// Admins can always propose access changes
		// Other members need the environments they're granting
		if member.Role != RoleAdmin {
			// Will be validated when the actual block is created
		}

	case ActionLeaveTeam:
		// Anyone can leave
		if member.Role == RoleAdmin && c.adminCount() == 1 {
			return errors.New("last admin cannot leave team")
		}

	case ActionRotateKey:
		// Anyone can rotate their own key

	case ActionDissolveTeam:
		// Only admins can propose dissolution
		if member.Role != RoleAdmin {
			return errors.New("only admins can dissolve a team")
		}

	default:
		return fmt.Errorf("unknown action: %s", action)
	}

	return nil
}

// EligibleApprovers returns members who can approve a block
func (c *Chain) EligibleApprovers(block *Block) []*Member {
	c.mu.RLock()
	defer c.mu.RUnlock()

	eligible := make([]*Member, 0)

	for _, member := range c.members {
		// Skip proposer
		if bytes.Equal(member.SigningPub, block.ProposedBy) {
			continue
		}

		// Skip those who already approved
		alreadyApproved := false
		for _, approval := range block.Approvals {
			if bytes.Equal(approval.By, member.SigningPub) {
				alreadyApproved = true
				break
			}
		}
		if alreadyApproved {
			continue
		}

		// For environment access changes, check env access
		if block.Action == ActionUpdateAccess {
			ac, err := block.GetAccessChange()
			if err != nil {
				continue
			}
			canApprove := true
			for _, env := range ac.Environments {
				if !c.hasEnvAccessLocked(member.SigningPub, env) {
					canApprove = false
					break
				}
			}
			if !canApprove {
				continue
			}
		}

		eligible = append(eligible, member)
	}

	return eligible
}

// ApprovalStatus returns the approval status of a block
type ApprovalStatus struct {
	Required  int
	Current   int
	Remaining int
	Complete  bool
	Approvers []string // Names of approvers
}

// GetApprovalStatus returns the approval status of a block
func (c *Chain) GetApprovalStatus(block *Block) *ApprovalStatus {
	required := c.RequiredApprovals(block)
	current := c.CountValidApprovals(block)

	c.mu.RLock()
	approvers := make([]string, 0)
	for _, approval := range block.Approvals {
		if member := c.members[string(approval.By)]; member != nil {
			approvers = append(approvers, member.Name)
		}
	}
	c.mu.RUnlock()

	remaining := required - current
	if remaining < 0 {
		remaining = 0
	}

	return &ApprovalStatus{
		Required:  required,
		Current:   current,
		Remaining: remaining,
		Complete:  current >= required,
		Approvers: approvers,
	}
}
