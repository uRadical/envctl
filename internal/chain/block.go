package chain

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"uradical.io/go/envctl/internal/crypto"
)

// Action represents the type of chain operation
type Action string

const (
	ActionCreateTeam   Action = "create_team"   // Genesis block
	ActionAddMember    Action = "add_member"    // Add new member
	ActionRemoveMember Action = "remove_member" // Remove member
	ActionChangeRole   Action = "change_role"   // Change member role
	ActionRotateKey    Action = "rotate_key"    // Key rotation
	ActionUpdatePolicy Action = "update_policy" // Update team policy
	ActionUpdateAccess Action = "update_access" // Update environment access
	ActionLeaveTeam    Action = "leave_team"    // Self-removal
	ActionAddEnv       Action = "add_env"       // Add environment
	ActionRemoveEnv    Action = "remove_env"    // Remove environment
	ActionDissolveTeam Action = "dissolve_team" // Dissolve team (irreversible)
	ActionInvite       Action = "invite"        // Create invite code
	ActionRevokeInvite Action = "revoke_invite" // Revoke unused invite
)

// Role represents a team member's role
type Role string

const (
	RoleAdmin  Role = "admin"  // Full access, can manage members and environments (lead)
	RoleMember Role = "member" // Read/write access to secrets
	RoleReader Role = "reader" // Read-only access to secrets
)

// CanManageMembers returns true if the role can add/remove members
func (r Role) CanManageMembers() bool {
	return r == RoleAdmin
}

// CanManageEnvironments returns true if the role can create/delete environments
func (r Role) CanManageEnvironments() bool {
	return r == RoleAdmin
}

// CanWrite returns true if the role can modify secrets
func (r Role) CanWrite() bool {
	return r == RoleAdmin || r == RoleMember
}

// CanRead returns true if the role can read secrets
func (r Role) CanRead() bool {
	return r == RoleAdmin || r == RoleMember || r == RoleReader
}

// Valid returns true if the role is a valid role
func (r Role) Valid() bool {
	return r == RoleAdmin || r == RoleMember || r == RoleReader
}

// Block represents a block in the team membership chain
type Block struct {
	Index      uint64          `json:"index"`
	Timestamp  time.Time       `json:"timestamp"`
	PrevHash   []byte          `json:"prev_hash"`
	Action     Action          `json:"action"`
	Subject    json.RawMessage `json:"subject"`
	ProposedBy []byte          `json:"proposed_by"` // Signing public key
	Approvals  []Approval      `json:"approvals"`
	SigAlgo    string          `json:"sig_algo"`
	Signature  []byte          `json:"signature"` // Signature by proposer over block content
	Hash       []byte          `json:"hash"`
}

// Approval represents an approval signature for a block
type Approval struct {
	By        []byte    `json:"by"`      // Signing public key
	SigAlgo   string    `json:"sig_algo"`
	Signature []byte    `json:"signature"`
	Timestamp time.Time `json:"timestamp"`
}

// Member represents a team member
type Member struct {
	Name         string    `json:"name"`
	MLKEMPub     []byte    `json:"mlkem_pub"`
	SigningPub   []byte    `json:"signing_pub"`
	Role         Role      `json:"role"`
	Environments []string  `json:"environments"`          // Environment access list
	JoinedAt     time.Time `json:"joined_at"`
	InviteCode   string    `json:"invite_code,omitempty"` // Links to invite block that authorized join
}

// Invite represents an invitation to join the project
type Invite struct {
	Code         string    `json:"code"`         // 8-12 char alphanumeric code (e.g., "ABC-123-XYZ")
	Name         string    `json:"name"`         // Display name for invitee
	PubKeyHash   string    `json:"pubkey_hash"`  // SHA256 of invited signing pubkey (hex)
	Role         Role      `json:"role"`         // Role to assign on join
	Environments []string  `json:"environments"` // Env access to grant on join
	CreatedAt    time.Time `json:"created_at"`   // When invite was created
	ExpiresAt    time.Time `json:"expires_at"`   // When invite expires
}

// InviteRevocation marks an invite as revoked
type InviteRevocation struct {
	Code   string `json:"code"`             // Code being revoked
	Reason string `json:"reason,omitempty"` // Optional reason for revocation
}

// Policy represents team policy stored in genesis block
type Policy struct {
	TeamName          string        `json:"team_name"`
	Environments      []string      `json:"environments"`       // Available environments
	DefaultAccess     []string      `json:"default_access"`     // Default env access for new members
	MinApprovals      int           `json:"min_approvals"`      // Minimum approvals required
	ApprovalThreshold float64       `json:"approval_threshold"` // Approval percentage threshold
	RequestExpiry     time.Duration `json:"request_expiry"`     // Request timeout
	MaxEnvSize        int64         `json:"max_env_size"`       // Max env file size in bytes
	Relay             string        `json:"relay,omitempty"`    // Future: relay server
	AllowRelay        bool          `json:"allow_relay"`        // Future: allow relay
	SoloMode          bool          `json:"solo_mode"`          // Allow single-admin teams without approvals
}

// RoleChange represents a role change action subject
type RoleChange struct {
	Member  []byte `json:"member"`   // Signing public key
	NewRole Role   `json:"new_role"`
}

// AccessChange represents an environment access change
type AccessChange struct {
	Member       []byte   `json:"member"`
	Environments []string `json:"environments"`
	Action       string   `json:"action"` // "grant" or "revoke"
}

// EnvChange represents an environment add/remove action
type EnvChange struct {
	Environment string   `json:"environment"`
	RevokedFrom [][]byte `json:"revoked_from,omitempty"` // Members who lost access (for remove)
}

// DissolveSubject is the subject for dissolve_team action
type DissolveSubject struct {
	Reason string `json:"reason,omitempty"`
}

// DefaultPolicy returns a sensible default policy
func DefaultPolicy(teamName string) *Policy {
	return &Policy{
		TeamName:          teamName,
		Environments:      []string{"dev", "stage", "prod"},
		DefaultAccess:     []string{"dev"},
		MinApprovals:      2,
		ApprovalThreshold: 0.5,
		RequestExpiry:     72 * time.Hour,
		MaxEnvSize:        10 * 1024 * 1024, // 10 MB
		AllowRelay:        false,
	}
}

// NewPolicy creates a policy with custom environments
func NewPolicy(teamName string, envs []string, defaultAccess []string) *Policy {
	p := DefaultPolicy(teamName)
	p.Environments = envs
	p.DefaultAccess = defaultAccess
	return p
}

// NewGenesisBlock creates the genesis block for a new team
func NewGenesisBlock(creator *crypto.Identity, policy *Policy) (*Block, error) {
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}

	// Create the founding member
	founder := Member{
		Name:         creator.Name,
		MLKEMPub:     creator.MLKEMPublicKey(),
		SigningPub:   creator.SigningPublicKey(),
		Role:         RoleAdmin,
		Environments: policy.Environments, // Admin gets all environments
		JoinedAt:     time.Now().UTC(),
	}

	// Genesis subject includes both policy and founder
	genesisSubject := struct {
		Policy  *Policy `json:"policy"`
		Founder Member  `json:"founder"`
	}{
		Policy:  policy,
		Founder: founder,
	}

	subjectJSON, err := json.Marshal(genesisSubject)
	if err != nil {
		return nil, fmt.Errorf("marshal subject: %w", err)
	}

	// Create genesis block (no previous hash)
	block := &Block{
		Index:      0,
		Timestamp:  time.Now().UTC(),
		PrevHash:   nil,
		Action:     ActionCreateTeam,
		Subject:    subjectJSON,
		ProposedBy: creator.SigningPublicKey(),
		Approvals:  nil, // Genesis needs no approvals
		SigAlgo:    crypto.AlgorithmEd25519,
	}

	// Compute hash and sign
	if err := block.computeHashAndSign(creator); err != nil {
		return nil, err
	}

	_ = policyJSON // Used in subject construction above

	return block, nil
}

// NewBlock creates a new block with the given action and subject
func NewBlock(prevBlock *Block, action Action, subject interface{}, proposer *crypto.Identity) (*Block, error) {
	subjectJSON, err := json.Marshal(subject)
	if err != nil {
		return nil, fmt.Errorf("marshal subject: %w", err)
	}

	block := &Block{
		Index:      prevBlock.Index + 1,
		Timestamp:  time.Now().UTC(),
		PrevHash:   prevBlock.Hash,
		Action:     action,
		Subject:    subjectJSON,
		ProposedBy: proposer.SigningPublicKey(),
		Approvals:  nil,
		SigAlgo:    crypto.AlgorithmEd25519,
	}

	// Compute hash and sign
	if err := block.computeHashAndSign(proposer); err != nil {
		return nil, err
	}

	return block, nil
}

// computeHashAndSign computes the block hash and signs it
func (b *Block) computeHashAndSign(signer *crypto.Identity) error {
	// Compute hash over block content (excluding signature and hash)
	hashData := b.hashableContent()
	hash := sha256.Sum256(hashData)
	b.Hash = hash[:]

	// Sign the hash
	b.Signature = signer.Sign(b.Hash)

	return nil
}

// hashableContent returns the content to be hashed
func (b *Block) hashableContent() []byte {
	// We hash everything except the final signature and hash
	content := struct {
		Index      uint64          `json:"index"`
		Timestamp  time.Time       `json:"timestamp"`
		PrevHash   []byte          `json:"prev_hash"`
		Action     Action          `json:"action"`
		Subject    json.RawMessage `json:"subject"`
		ProposedBy []byte          `json:"proposed_by"`
		Approvals  []Approval      `json:"approvals"`
		SigAlgo    string          `json:"sig_algo"`
	}{
		Index:      b.Index,
		Timestamp:  b.Timestamp,
		PrevHash:   b.PrevHash,
		Action:     b.Action,
		Subject:    b.Subject,
		ProposedBy: b.ProposedBy,
		Approvals:  b.Approvals,
		SigAlgo:    b.SigAlgo,
	}

	data, _ := json.Marshal(content)
	return data
}

// VerifyHash verifies the block's hash is correct
func (b *Block) VerifyHash() bool {
	hashData := b.hashableContent()
	expectedHash := sha256.Sum256(hashData)
	return string(b.Hash) == string(expectedHash[:])
}

// VerifySignature verifies the block's signature
func (b *Block) VerifySignature() bool {
	ok, _ := crypto.VerifySignature(b.SigAlgo, b.ProposedBy, b.Hash, b.Signature)
	return ok
}

// VerifyChainLink verifies this block links to the previous block correctly
func (b *Block) VerifyChainLink(prevBlock *Block) bool {
	if b.Index != prevBlock.Index+1 {
		return false
	}
	return string(b.PrevHash) == string(prevBlock.Hash)
}

// AddApproval adds an approval to the block
func (b *Block) AddApproval(approver *crypto.Identity) error {
	// Create approval signature over the block hash
	signature := approver.Sign(b.Hash)

	approval := Approval{
		By:        approver.SigningPublicKey(),
		SigAlgo:   crypto.AlgorithmEd25519,
		Signature: signature,
		Timestamp: time.Now().UTC(),
	}

	b.Approvals = append(b.Approvals, approval)
	return nil
}

// VerifyApproval verifies a single approval signature
func (b *Block) VerifyApproval(approval *Approval) bool {
	ok, _ := crypto.VerifySignature(approval.SigAlgo, approval.By, b.Hash, approval.Signature)
	return ok
}

// VerifyAllApprovals verifies all approval signatures
func (b *Block) VerifyAllApprovals() bool {
	for i := range b.Approvals {
		if !b.VerifyApproval(&b.Approvals[i]) {
			return false
		}
	}
	return true
}

// GetMember parses the subject as a Member (for add_member action)
func (b *Block) GetMember() (*Member, error) {
	if b.Action != ActionAddMember {
		return nil, errors.New("block action is not add_member")
	}

	var member Member
	if err := json.Unmarshal(b.Subject, &member); err != nil {
		return nil, fmt.Errorf("parse member: %w", err)
	}
	return &member, nil
}

// GetRemovedMember parses the subject as the removed member's public key
func (b *Block) GetRemovedMember() ([]byte, error) {
	if b.Action != ActionRemoveMember && b.Action != ActionLeaveTeam {
		return nil, errors.New("block action is not remove_member or leave_team")
	}

	var pubkey []byte
	if err := json.Unmarshal(b.Subject, &pubkey); err != nil {
		return nil, fmt.Errorf("parse removed member: %w", err)
	}
	return pubkey, nil
}

// GetRoleChange parses the subject as a RoleChange
func (b *Block) GetRoleChange() (*RoleChange, error) {
	if b.Action != ActionChangeRole {
		return nil, errors.New("block action is not change_role")
	}

	var rc RoleChange
	if err := json.Unmarshal(b.Subject, &rc); err != nil {
		return nil, fmt.Errorf("parse role change: %w", err)
	}
	return &rc, nil
}

// GetAccessChange parses the subject as an AccessChange
func (b *Block) GetAccessChange() (*AccessChange, error) {
	if b.Action != ActionUpdateAccess {
		return nil, errors.New("block action is not update_access")
	}

	var ac AccessChange
	if err := json.Unmarshal(b.Subject, &ac); err != nil {
		return nil, fmt.Errorf("parse access change: %w", err)
	}
	return &ac, nil
}

// GetPolicy parses the genesis block subject to extract policy
func (b *Block) GetPolicy() (*Policy, error) {
	if b.Action != ActionCreateTeam {
		return nil, errors.New("block action is not create_team")
	}

	var genesisSubject struct {
		Policy  *Policy `json:"policy"`
		Founder Member  `json:"founder"`
	}
	if err := json.Unmarshal(b.Subject, &genesisSubject); err != nil {
		return nil, fmt.Errorf("parse genesis subject: %w", err)
	}
	return genesisSubject.Policy, nil
}

// GetFounder parses the genesis block subject to extract founder
func (b *Block) GetFounder() (*Member, error) {
	if b.Action != ActionCreateTeam {
		return nil, errors.New("block action is not create_team")
	}

	var genesisSubject struct {
		Policy  *Policy `json:"policy"`
		Founder Member  `json:"founder"`
	}
	if err := json.Unmarshal(b.Subject, &genesisSubject); err != nil {
		return nil, fmt.Errorf("parse genesis subject: %w", err)
	}
	return &genesisSubject.Founder, nil
}

// GetEnvChange parses the subject as an EnvChange
func (b *Block) GetEnvChange() (*EnvChange, error) {
	if b.Action != ActionAddEnv && b.Action != ActionRemoveEnv {
		return nil, errors.New("block action is not add_env or remove_env")
	}

	var ec EnvChange
	if err := json.Unmarshal(b.Subject, &ec); err != nil {
		return nil, fmt.Errorf("parse env change: %w", err)
	}
	return &ec, nil
}

// GetDissolveSubject parses the subject as a DissolveSubject
func (b *Block) GetDissolveSubject() (*DissolveSubject, error) {
	if b.Action != ActionDissolveTeam {
		return nil, errors.New("block action is not dissolve_team")
	}

	var ds DissolveSubject
	if err := json.Unmarshal(b.Subject, &ds); err != nil {
		return nil, fmt.Errorf("parse dissolve subject: %w", err)
	}
	return &ds, nil
}

// GetInvite parses the subject as an Invite
func (b *Block) GetInvite() (*Invite, error) {
	if b.Action != ActionInvite {
		return nil, errors.New("block action is not invite")
	}

	var invite Invite
	if err := json.Unmarshal(b.Subject, &invite); err != nil {
		return nil, fmt.Errorf("parse invite: %w", err)
	}
	return &invite, nil
}

// GetInviteRevocation parses the subject as an InviteRevocation
func (b *Block) GetInviteRevocation() (*InviteRevocation, error) {
	if b.Action != ActionRevokeInvite {
		return nil, errors.New("block action is not revoke_invite")
	}

	var revocation InviteRevocation
	if err := json.Unmarshal(b.Subject, &revocation); err != nil {
		return nil, fmt.Errorf("parse invite revocation: %w", err)
	}
	return &revocation, nil
}
