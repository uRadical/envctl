package chain

import (
	"fmt"
	"math"
	"time"
)

// RequiredApprovals calculates the number of approvals needed based on team size
func (p *Policy) RequiredApprovals(teamSize int) int {
	// Solo mode: single-admin teams operate without approvals
	// This must be explicitly enabled in policy - default is to require approvals
	if teamSize == 1 && p.SoloMode {
		return 0
	}

	// Small team security: if there are other members, require at least 1 approval
	// This prevents admins from acting unilaterally in 2-3 person teams
	if teamSize > 1 && teamSize < 3 {
		return 1
	}

	// Calculate required approvals: max(min_approvals, ceil(team_size * threshold))
	thresholdApprovals := int(math.Ceil(float64(teamSize) * p.ApprovalThreshold))
	required := p.MinApprovals
	if thresholdApprovals > required {
		required = thresholdApprovals
	}

	// Don't require more approvals than available members minus proposer
	maxPossible := teamSize - 1
	if required > maxPossible {
		required = maxPossible
	}

	return required
}

// ValidateEnvAccess checks if a member has access to an environment
func (p *Policy) ValidateEnvAccess(member *Member, env string) bool {
	for _, e := range member.Environments {
		if e == env {
			return true
		}
	}
	return false
}

// IsValidEnvironment checks if an environment is valid for this team
func (p *Policy) IsValidEnvironment(env string) bool {
	for _, e := range p.Environments {
		if e == env {
			return true
		}
	}
	return false
}

// DefaultAccessList returns the default access list for new members
func (p *Policy) DefaultAccessList() []string {
	result := make([]string, len(p.DefaultAccess))
	copy(result, p.DefaultAccess)
	return result
}

// IsRequestExpired checks if a request has expired based on policy
func (p *Policy) IsRequestExpired(requestTime time.Time) bool {
	if p.RequestExpiry == 0 {
		return false
	}
	return time.Since(requestTime) > p.RequestExpiry
}

// ValidateEnvSize checks if an env file size is within policy limits
func (p *Policy) ValidateEnvSize(size int64) bool {
	if p.MaxEnvSize == 0 {
		return true
	}
	return size <= p.MaxEnvSize
}

// AllEnvironments returns all defined environments
func (p *Policy) AllEnvironments() []string {
	result := make([]string, len(p.Environments))
	copy(result, p.Environments)
	return result
}

// WithDefaults returns a policy with any zero values set to defaults
func (p *Policy) WithDefaults() *Policy {
	defaults := DefaultPolicy(p.TeamName)

	result := *p

	if len(result.Environments) == 0 {
		result.Environments = defaults.Environments
	}
	if len(result.DefaultAccess) == 0 {
		result.DefaultAccess = defaults.DefaultAccess
	}
	if result.MinApprovals == 0 {
		result.MinApprovals = defaults.MinApprovals
	}
	if result.ApprovalThreshold == 0 {
		result.ApprovalThreshold = defaults.ApprovalThreshold
	}
	if result.RequestExpiry == 0 {
		result.RequestExpiry = defaults.RequestExpiry
	}
	if result.MaxEnvSize == 0 {
		result.MaxEnvSize = defaults.MaxEnvSize
	}

	return &result
}

// Clone returns a deep copy of the policy
func (p *Policy) Clone() *Policy {
	clone := *p

	clone.Environments = make([]string, len(p.Environments))
	copy(clone.Environments, p.Environments)

	clone.DefaultAccess = make([]string, len(p.DefaultAccess))
	copy(clone.DefaultAccess, p.DefaultAccess)

	return &clone
}

// AddEnvironment adds a new environment to the policy
func (p *Policy) AddEnvironment(env string) error {
	if p.IsValidEnvironment(env) {
		return fmt.Errorf("environment '%s' already exists", env)
	}
	p.Environments = append(p.Environments, env)
	return nil
}

// RemoveEnvironment removes an environment from the policy
func (p *Policy) RemoveEnvironment(env string) error {
	if !p.IsValidEnvironment(env) {
		return fmt.Errorf("environment '%s' does not exist", env)
	}

	// Don't allow removing the last environment
	if len(p.Environments) == 1 {
		return fmt.Errorf("cannot remove last environment")
	}

	// Remove from default access if present
	p.DefaultAccess = removeFromSlice(p.DefaultAccess, env)

	// Remove from environments
	p.Environments = removeFromSlice(p.Environments, env)

	return nil
}

// removeFromSlice removes an item from a string slice
func removeFromSlice(slice []string, item string) []string {
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}
