package chain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"uradical.io/go/envctl/internal/crypto"
)

// Chain represents a team membership blockchain
type Chain struct {
	mu      sync.RWMutex
	blocks  []*Block
	members map[string]*Member // Key: hex(SigningPub)
	policy  *Policy

	// Dissolved state
	dissolved   bool
	dissolvedAt time.Time
	dissolvedBy []byte // Signing public key of proposer
}

// New creates a new empty chain
func New() *Chain {
	return &Chain{
		blocks:  make([]*Block, 0),
		members: make(map[string]*Member),
	}
}

// NewFromGenesis creates a chain from a genesis block
func NewFromGenesis(genesis *Block) (*Chain, error) {
	if genesis.Index != 0 || genesis.Action != ActionCreateTeam {
		return nil, errors.New("invalid genesis block")
	}

	chain := New()
	if err := chain.AppendBlock(genesis); err != nil {
		return nil, err
	}

	return chain, nil
}

// FromBlocks creates a chain from a list of blocks
// The blocks must be in order and form a valid chain starting from genesis
func FromBlocks(blocks []*Block) (*Chain, error) {
	if len(blocks) == 0 {
		return nil, errors.New("no blocks provided")
	}

	// First block must be genesis
	genesis := blocks[0]
	if genesis.Index != 0 || genesis.Action != ActionCreateTeam {
		return nil, errors.New("first block is not a valid genesis block")
	}

	chain := New()

	// Append all blocks in order
	for _, block := range blocks {
		if err := chain.AppendBlock(block); err != nil {
			return nil, fmt.Errorf("append block %d: %w", block.Index, err)
		}
	}

	return chain, nil
}

// CreateTeam creates a new team chain with the given identity as founder
func CreateTeam(teamName string, founder *crypto.Identity) (*Chain, error) {
	policy := DefaultPolicy(teamName)
	genesis, err := NewGenesisBlock(founder, policy)
	if err != nil {
		return nil, fmt.Errorf("create genesis block: %w", err)
	}

	return NewFromGenesis(genesis)
}

// CreateTeamWithEnvs creates a new team chain with custom environments
func CreateTeamWithEnvs(teamName string, founder *crypto.Identity, envs []string, defaultAccess []string) (*Chain, error) {
	policy := NewPolicy(teamName, envs, defaultAccess)
	genesis, err := NewGenesisBlock(founder, policy)
	if err != nil {
		return nil, fmt.Errorf("create genesis block: %w", err)
	}

	return NewFromGenesis(genesis)
}

// Len returns the number of blocks in the chain
func (c *Chain) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.blocks)
}

// Head returns the latest block in the chain
func (c *Chain) Head() *Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.blocks) == 0 {
		return nil
	}
	return c.blocks[len(c.blocks)-1]
}

// Genesis returns the genesis block
func (c *Chain) Genesis() *Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.blocks) == 0 {
		return nil
	}
	return c.blocks[0]
}

// Block returns a block by index
func (c *Chain) Block(index uint64) *Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if int(index) >= len(c.blocks) {
		return nil
	}
	return c.blocks[index]
}

// Blocks returns all blocks from startIndex
func (c *Chain) Blocks(startIndex uint64) []*Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if int(startIndex) >= len(c.blocks) {
		return nil
	}
	result := make([]*Block, len(c.blocks)-int(startIndex))
	copy(result, c.blocks[startIndex:])
	return result
}

// Policy returns the team policy
func (c *Chain) Policy() *Policy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policy
}

// TeamName returns the team name
func (c *Chain) TeamName() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.policy == nil {
		return ""
	}
	return c.policy.TeamName
}

// IsDissolved returns true if the team has been dissolved
func (c *Chain) IsDissolved() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.dissolved
}

// DissolvedAt returns when the team was dissolved (zero if not dissolved)
func (c *Chain) DissolvedAt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.dissolvedAt
}

// Members returns all current members
func (c *Chain) Members() []*Member {
	c.mu.RLock()
	defer c.mu.RUnlock()
	members := make([]*Member, 0, len(c.members))
	for _, m := range c.members {
		members = append(members, m)
	}
	return members
}

// MemberCount returns the number of current members
func (c *Chain) MemberCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.members)
}

// Member returns a member by their signing public key
func (c *Chain) Member(signingPub []byte) *Member {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.members[string(signingPub)]
}

// IsMember checks if a public key belongs to a current member
func (c *Chain) IsMember(signingPub []byte) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.members[string(signingPub)]
	return ok
}

// IsAdmin checks if a public key belongs to an admin
func (c *Chain) IsAdmin(signingPub []byte) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	member, ok := c.members[string(signingPub)]
	return ok && member.Role == RoleAdmin
}

// Admins returns all admin members
func (c *Chain) Admins() []*Member {
	c.mu.RLock()
	defer c.mu.RUnlock()
	admins := make([]*Member, 0)
	for _, m := range c.members {
		if m.Role == RoleAdmin {
			admins = append(admins, m)
		}
	}
	return admins
}

// HasEnvAccess checks if a member has access to an environment
func (c *Chain) HasEnvAccess(signingPub []byte, env string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	member, ok := c.members[string(signingPub)]
	if !ok {
		return false
	}
	for _, e := range member.Environments {
		if e == env {
			return true
		}
	}
	return false
}

// MembersWithEnvAccess returns all members with access to an environment
func (c *Chain) MembersWithEnvAccess(env string) []*Member {
	c.mu.RLock()
	defer c.mu.RUnlock()
	members := make([]*Member, 0)
	for _, m := range c.members {
		for _, e := range m.Environments {
			if e == env {
				members = append(members, m)
				break
			}
		}
	}
	return members
}

// AppendBlock validates and appends a block to the chain
func (c *Chain) AppendBlock(block *Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if chain is dissolved (only allow dissolve block itself)
	if c.dissolved && block.Action != ActionDissolveTeam {
		return errors.New("team has been dissolved")
	}

	// Prevent double dissolution
	if block.Action == ActionDissolveTeam && c.dissolved {
		return errors.New("team is already dissolved")
	}

	// Validate block
	if err := c.validateBlock(block); err != nil {
		return err
	}

	// Apply block to state
	if err := c.applyBlock(block); err != nil {
		return err
	}

	c.blocks = append(c.blocks, block)
	return nil
}

// validateBlock validates a block before appending
func (c *Chain) validateBlock(block *Block) error {
	// Verify hash
	if !block.VerifyHash() {
		return errors.New("invalid block hash")
	}

	// Verify signature
	if !block.VerifySignature() {
		return errors.New("invalid block signature")
	}

	// Verify all approvals
	if !block.VerifyAllApprovals() {
		return errors.New("invalid approval signature")
	}

	// Check chain linkage
	if len(c.blocks) == 0 {
		// Genesis block
		if block.Index != 0 || block.Action != ActionCreateTeam {
			return errors.New("first block must be genesis")
		}
		if block.PrevHash != nil {
			return errors.New("genesis block cannot have previous hash")
		}
	} else {
		// Non-genesis block
		prevBlock := c.blocks[len(c.blocks)-1]
		if !block.VerifyChainLink(prevBlock) {
			return errors.New("block does not link to previous block")
		}

		// Verify proposer is a member (except for genesis)
		if !c.IsMemberLocked(block.ProposedBy) {
			return errors.New("proposer is not a team member")
		}

		// Verify action permissions
		if err := c.verifyActionPermissions(block); err != nil {
			return err
		}
	}

	return nil
}

// IsMemberLocked checks membership without locking (for internal use)
func (c *Chain) IsMemberLocked(signingPub []byte) bool {
	_, ok := c.members[string(signingPub)]
	return ok
}

// verifyActionPermissions verifies the proposer has permission for the action
func (c *Chain) verifyActionPermissions(block *Block) error {
	member := c.members[string(block.ProposedBy)]
	if member == nil {
		return errors.New("proposer not found")
	}

	switch block.Action {
	case ActionAddMember, ActionRemoveMember, ActionChangeRole, ActionUpdatePolicy:
		// These require admin role
		if member.Role != RoleAdmin {
			return fmt.Errorf("action %s requires admin role", block.Action)
		}

	case ActionUpdateAccess:
		// Admins can grant/revoke access
		// Members with access to an env can grant that env to others
		if member.Role != RoleAdmin {
			ac, err := block.GetAccessChange()
			if err != nil {
				return err
			}
			// Check proposer has access to all environments being changed
			for _, env := range ac.Environments {
				if !c.hasEnvAccessLocked(block.ProposedBy, env) {
					return fmt.Errorf("proposer does not have access to environment %s", env)
				}
			}
		}

	case ActionLeaveTeam:
		// Self-removal - proposer must be removing themselves
		removedPub, err := block.GetRemovedMember()
		if err != nil {
			return err
		}
		if !bytes.Equal(removedPub, block.ProposedBy) {
			return errors.New("leave_team action must be self-removal")
		}
		// Check if this is the last admin
		if member.Role == RoleAdmin && c.adminCount() == 1 {
			return errors.New("last admin cannot leave team")
		}

	case ActionRotateKey:
		// Member can rotate their own key
		// This is handled specially

	case ActionAddEnv, ActionRemoveEnv:
		// Environment changes require admin role
		if member.Role != RoleAdmin {
			return fmt.Errorf("action %s requires admin role", block.Action)
		}

	case ActionDissolveTeam:
		// Only admins can dissolve a team
		if member.Role != RoleAdmin {
			return errors.New("only admins can dissolve a team")
		}

	case ActionInvite:
		// Only admins can create invites
		if member.Role != RoleAdmin {
			return errors.New("only admins can create invites")
		}

	case ActionRevokeInvite:
		// Only admins can revoke invites
		if member.Role != RoleAdmin {
			return errors.New("only admins can revoke invites")
		}

	default:
		return fmt.Errorf("unknown action: %s", block.Action)
	}

	return nil
}

func (c *Chain) hasEnvAccessLocked(signingPub []byte, env string) bool {
	member := c.members[string(signingPub)]
	if member == nil {
		return false
	}
	for _, e := range member.Environments {
		if e == env {
			return true
		}
	}
	return false
}

func (c *Chain) adminCount() int {
	count := 0
	for _, m := range c.members {
		if m.Role == RoleAdmin {
			count++
		}
	}
	return count
}

// applyBlock applies a block's changes to the chain state
func (c *Chain) applyBlock(block *Block) error {
	switch block.Action {
	case ActionCreateTeam:
		// Extract policy and founder from genesis
		policy, err := block.GetPolicy()
		if err != nil {
			return err
		}
		founder, err := block.GetFounder()
		if err != nil {
			return err
		}
		c.policy = policy
		c.members[string(founder.SigningPub)] = founder

	case ActionAddMember:
		member, err := block.GetMember()
		if err != nil {
			return err
		}
		c.members[string(member.SigningPub)] = member

	case ActionRemoveMember, ActionLeaveTeam:
		pubkey, err := block.GetRemovedMember()
		if err != nil {
			return err
		}
		delete(c.members, string(pubkey))

	case ActionChangeRole:
		rc, err := block.GetRoleChange()
		if err != nil {
			return err
		}
		member := c.members[string(rc.Member)]
		if member != nil {
			member.Role = rc.NewRole
		}

	case ActionUpdateAccess:
		ac, err := block.GetAccessChange()
		if err != nil {
			return err
		}
		member := c.members[string(ac.Member)]
		if member != nil {
			if ac.Action == "grant" {
				// Add environments
				for _, env := range ac.Environments {
					found := false
					for _, e := range member.Environments {
						if e == env {
							found = true
							break
						}
					}
					if !found {
						member.Environments = append(member.Environments, env)
					}
				}
			} else if ac.Action == "revoke" {
				// Remove environments
				newEnvs := make([]string, 0)
				for _, e := range member.Environments {
					remove := false
					for _, env := range ac.Environments {
						if e == env {
							remove = true
							break
						}
					}
					if !remove {
						newEnvs = append(newEnvs, e)
					}
				}
				member.Environments = newEnvs
			}
		}

	case ActionUpdatePolicy:
		var newPolicy Policy
		if err := block.ParseSubject(&newPolicy); err != nil {
			return err
		}
		c.policy = &newPolicy

	case ActionRotateKey:
		// Key rotation is complex - needs special handling
		// For now, just mark as applied

	case ActionInvite:
		// Invites are stored in blocks and reconstructed by scanning
		// No in-memory state change needed

	case ActionAddEnv:
		ec, err := block.GetEnvChange()
		if err != nil {
			return err
		}
		if err := c.policy.AddEnvironment(ec.Environment); err != nil {
			return err
		}

	case ActionRemoveEnv:
		ec, err := block.GetEnvChange()
		if err != nil {
			return err
		}
		// Revoke access from members listed in RevokedFrom
		for _, pubkey := range ec.RevokedFrom {
			if member := c.members[string(pubkey)]; member != nil {
				member.Environments = removeEnvFromList(member.Environments, ec.Environment)
			}
		}
		if err := c.policy.RemoveEnvironment(ec.Environment); err != nil {
			return err
		}

	case ActionDissolveTeam:
		// Mark chain as dissolved
		c.dissolved = true
		c.dissolvedAt = block.Timestamp
		c.dissolvedBy = block.ProposedBy

	default:
		return fmt.Errorf("unknown action: %s", block.Action)
	}

	return nil
}

// removeEnvFromList removes an environment from a list
func removeEnvFromList(envs []string, env string) []string {
	result := make([]string, 0, len(envs))
	for _, e := range envs {
		if e != env {
			result = append(result, e)
		}
	}
	return result
}

// Verify validates the entire chain
func (c *Chain) Verify() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.blocks) == 0 {
		return errors.New("empty chain")
	}

	// Verify genesis
	genesis := c.blocks[0]
	if genesis.Index != 0 || genesis.Action != ActionCreateTeam {
		return errors.New("invalid genesis block")
	}
	if !genesis.VerifyHash() {
		return errors.New("genesis: invalid hash")
	}
	if !genesis.VerifySignature() {
		return errors.New("genesis: invalid signature")
	}

	// Verify each subsequent block
	for i := 1; i < len(c.blocks); i++ {
		block := c.blocks[i]
		prevBlock := c.blocks[i-1]

		if !block.VerifyHash() {
			return fmt.Errorf("block %d: invalid hash", i)
		}
		if !block.VerifySignature() {
			return fmt.Errorf("block %d: invalid signature", i)
		}
		if !block.VerifyChainLink(prevBlock) {
			return fmt.Errorf("block %d: invalid chain link", i)
		}
		if !block.VerifyAllApprovals() {
			return fmt.Errorf("block %d: invalid approval signature", i)
		}
	}

	return nil
}

// ParseSubject is a helper to parse block subject
func (b *Block) ParseSubject(v interface{}) error {
	return json.Unmarshal(b.Subject, v)
}

// FindMemberByName finds a member by name
func (c *Chain) FindMemberByName(name string) *Member {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, m := range c.members {
		if m.Name == name {
			return m
		}
	}
	return nil
}

// FindInvite looks up an invite by code
func (c *Chain) FindInvite(code string) (*Invite, *Block, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	normalizedCode := NormalizeInviteCode(code)
	for _, block := range c.blocks {
		if block.Action == ActionInvite {
			invite, err := block.GetInvite()
			if err != nil {
				continue
			}
			if NormalizeInviteCode(invite.Code) == normalizedCode {
				return invite, block, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("invite not found")
}

// IsInviteUsed checks if an invite code has been consumed by a member join
func (c *Chain) IsInviteUsed(code string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	normalizedCode := NormalizeInviteCode(code)
	for _, block := range c.blocks {
		if block.Action == ActionAddMember {
			member, err := block.GetMember()
			if err != nil {
				continue
			}
			if NormalizeInviteCode(member.InviteCode) == normalizedCode {
				return true
			}
		}
	}
	return false
}

// IsInviteRevoked checks if an invite has been revoked
func (c *Chain) IsInviteRevoked(code string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	normalizedCode := NormalizeInviteCode(code)
	for _, block := range c.blocks {
		if block.Action == ActionRevokeInvite {
			revocation, err := block.GetInviteRevocation()
			if err != nil {
				continue
			}
			if NormalizeInviteCode(revocation.Code) == normalizedCode {
				return true
			}
		}
	}
	return false
}

// ValidateInvite checks if an invite code is valid for the given pubkey
func (c *Chain) ValidateInvite(code string, pubkey []byte) (*Invite, error) {
	invite, _, err := c.FindInvite(code)
	if err != nil {
		return nil, fmt.Errorf("invalid invite code")
	}

	if c.IsInviteRevoked(code) {
		return nil, fmt.Errorf("invite code was revoked")
	}

	if c.IsInviteUsed(code) {
		return nil, fmt.Errorf("invite code already used")
	}

	if time.Now().After(invite.ExpiresAt) {
		return nil, fmt.Errorf("invite code expired")
	}

	// Verify pubkey matches the invited key hash
	pubkeyHash := crypto.HashPublicKey(pubkey)
	if pubkeyHash != invite.PubKeyHash {
		return nil, fmt.Errorf("public key doesn't match invited key")
	}

	return invite, nil
}

// GetAllInvites returns all invites with their status
type InviteStatus struct {
	Invite  *Invite
	Block   *Block
	Status  string // "pending", "used", "revoked", "expired"
	UsedBy  string // Member name if used
}

func (c *Chain) GetAllInvites() []*InviteStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var invites []*InviteStatus
	for _, block := range c.blocks {
		if block.Action == ActionInvite {
			invite, err := block.GetInvite()
			if err != nil {
				continue
			}

			status := &InviteStatus{
				Invite: invite,
				Block:  block,
				Status: "pending",
			}

			// Check status without lock (we already hold it)
			normalizedCode := NormalizeInviteCode(invite.Code)

			// Check if used
			for _, b := range c.blocks {
				if b.Action == ActionAddMember {
					member, err := b.GetMember()
					if err != nil {
						continue
					}
					if NormalizeInviteCode(member.InviteCode) == normalizedCode {
						status.Status = "used"
						status.UsedBy = member.Name
						break
					}
				}
			}

			// Check if revoked (only if not used)
			if status.Status == "pending" {
				for _, b := range c.blocks {
					if b.Action == ActionRevokeInvite {
						revocation, err := b.GetInviteRevocation()
						if err != nil {
							continue
						}
						if NormalizeInviteCode(revocation.Code) == normalizedCode {
							status.Status = "revoked"
							break
						}
					}
				}
			}

			// Check if expired (only if still pending)
			if status.Status == "pending" && time.Now().After(invite.ExpiresAt) {
				status.Status = "expired"
			}

			invites = append(invites, status)
		}
	}

	return invites
}
