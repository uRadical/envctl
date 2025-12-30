package chain

import (
	"bytes"
	"testing"
	"time"

	"uradical.io/go/envctl/internal/crypto"
)

// createTestChainWithMembers creates a chain with the specified number of members
func createTestChainWithMembers(t *testing.T, memberCount int) (*Chain, []*crypto.Identity) {
	t.Helper()

	identities := make([]*crypto.Identity, memberCount)
	for i := 0; i < memberCount; i++ {
		id, err := crypto.GenerateIdentity("member" + string(rune('A'+i)))
		if err != nil {
			t.Fatalf("generate identity %d: %v", i, err)
		}
		identities[i] = id
	}

	// Create chain with first identity as founder
	policy := DefaultPolicy("testteam")
	chain, err := CreateTeam("testteam", identities[0])
	if err != nil {
		t.Fatalf("create team: %v", err)
	}

	// Add remaining members as admins
	for i := 1; i < memberCount; i++ {
		member := Member{
			Name:         identities[i].Name,
			SigningPub:   identities[i].SigningPublicKey(),
			MLKEMPub:     identities[i].MLKEMPublicKey(),
			Role:         RoleAdmin,
			Environments: policy.Environments,
			JoinedAt:     time.Now().UTC(),
		}

		head := chain.Head()
		block, err := NewBlock(head, ActionAddMember, member, identities[0])
		if err != nil {
			t.Fatalf("create add_member block: %v", err)
		}

		// For teams with 2+ members, we need approval from others
		// But during bootstrap (single member), no approval needed
		if err := chain.AppendBlock(block); err != nil {
			t.Fatalf("append member %d: %v", i, err)
		}
	}

	return chain, identities
}

func TestCannotApproveOwnProposal(t *testing.T) {
	chain, identities := createTestChainWithMembers(t, 3)
	proposer := identities[0]
	approver := identities[1]

	// Create a proposal
	member := Member{
		Name:         "newmember",
		SigningPub:   []byte("newsigpub"),
		MLKEMPub:     []byte("newmlkempub"),
		Role:         RoleMember,
		Environments: []string{"dev"},
		JoinedAt:     time.Now().UTC(),
	}

	head := chain.Head()
	block, err := NewBlock(head, ActionAddMember, member, proposer)
	if err != nil {
		t.Fatalf("create block: %v", err)
	}

	// Proposer should NOT be able to approve their own proposal
	err = chain.CanApprove(block, proposer.SigningPublicKey())
	if err == nil {
		t.Error("Expected error when proposer tries to approve own proposal")
	}
	if err.Error() != "cannot approve your own proposal" {
		t.Errorf("Unexpected error: %v", err)
	}

	// Other member should be able to approve
	err = chain.CanApprove(block, approver.SigningPublicKey())
	if err != nil {
		t.Errorf("Other member should be able to approve: %v", err)
	}
}

func TestCountValidApprovalsExcludesProposer(t *testing.T) {
	chain, identities := createTestChainWithMembers(t, 3)
	proposer := identities[0]
	approver1 := identities[1]
	approver2 := identities[2]

	// Create a proposal
	member := Member{
		Name:         "newmember",
		SigningPub:   []byte("newsigpub"),
		MLKEMPub:     []byte("newmlkempub"),
		Role:         RoleMember,
		Environments: []string{"dev"},
		JoinedAt:     time.Now().UTC(),
	}

	head := chain.Head()
	block, err := NewBlock(head, ActionAddMember, member, proposer)
	if err != nil {
		t.Fatalf("create block: %v", err)
	}

	// Add proposer's own approval (should be ignored)
	block.AddApproval(proposer)

	// Count should be 0 - proposer's approval doesn't count
	count := chain.CountValidApprovals(block)
	if count != 0 {
		t.Errorf("CountValidApprovals = %d, want 0 (proposer approval should be ignored)", count)
	}

	// Add legitimate approval from approver1
	block.AddApproval(approver1)
	count = chain.CountValidApprovals(block)
	if count != 1 {
		t.Errorf("CountValidApprovals = %d, want 1", count)
	}

	// Add approval from approver2
	block.AddApproval(approver2)
	count = chain.CountValidApprovals(block)
	if count != 2 {
		t.Errorf("CountValidApprovals = %d, want 2", count)
	}
}

func TestEligibleApproversExcludesProposer(t *testing.T) {
	chain, identities := createTestChainWithMembers(t, 3)
	proposer := identities[0]

	// Create a proposal
	member := Member{
		Name:         "newmember",
		SigningPub:   []byte("newsigpub"),
		MLKEMPub:     []byte("newmlkempub"),
		Role:         RoleMember,
		Environments: []string{"dev"},
		JoinedAt:     time.Now().UTC(),
	}

	head := chain.Head()
	block, err := NewBlock(head, ActionAddMember, member, proposer)
	if err != nil {
		t.Fatalf("create block: %v", err)
	}

	eligible := chain.EligibleApprovers(block)

	// Should have 2 eligible approvers (all members except proposer)
	if len(eligible) != 2 {
		t.Errorf("EligibleApprovers count = %d, want 2", len(eligible))
	}

	// Proposer should not be in the list
	for _, e := range eligible {
		if bytes.Equal(e.SigningPub, proposer.SigningPublicKey()) {
			t.Error("Proposer should not be in eligible approvers list")
		}
	}
}

func TestRequiredApprovalsForTeamSizes(t *testing.T) {
	tests := []struct {
		name       string
		memberCount int
		soloMode   bool
		expected   int
	}{
		{"solo_mode_enabled", 1, true, 0},
		{"solo_mode_disabled", 1, false, 0}, // maxPossible = 0
		{"two_members", 2, false, 1},
		{"three_members", 3, false, 2}, // ceil(3 * 0.5) = 2
		{"four_members", 4, false, 2},  // ceil(4 * 0.5) = 2
		{"five_members", 5, false, 3},  // ceil(5 * 0.5) = 3
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain, identities := createTestChainWithMembers(t, tc.memberCount)

			// Update policy if needed
			if tc.soloMode {
				chain.policy.SoloMode = true
			}

			// Create a test block
			member := Member{
				Name:         "newmember",
				SigningPub:   []byte("newsigpub"),
				MLKEMPub:     []byte("newmlkempub"),
				Role:         RoleMember,
				Environments: []string{"dev"},
				JoinedAt:     time.Now().UTC(),
			}

			head := chain.Head()
			block, err := NewBlock(head, ActionAddMember, member, identities[0])
			if err != nil {
				t.Fatalf("create block: %v", err)
			}

			required := chain.RequiredApprovals(block)
			if required != tc.expected {
				t.Errorf("RequiredApprovals = %d, want %d", required, tc.expected)
			}
		})
	}
}

func TestLeaveTeamNoApprovalsNeeded(t *testing.T) {
	chain, identities := createTestChainWithMembers(t, 3)
	leaver := identities[1] // Non-founding admin

	head := chain.Head()
	// Leave team uses the leaver's public key as subject
	block, err := NewBlock(head, ActionLeaveTeam, leaver.SigningPublicKey(), leaver)
	if err != nil {
		t.Fatalf("create block: %v", err)
	}

	required := chain.RequiredApprovals(block)
	if required != 0 {
		t.Errorf("LeaveTeam should require 0 approvals, got %d", required)
	}
}

func TestAddEnvNoApprovalsNeeded(t *testing.T) {
	chain, identities := createTestChainWithMembers(t, 3)

	head := chain.Head()
	envChange := EnvChange{Environment: "newenv"}
	block, err := NewBlock(head, ActionAddEnv, envChange, identities[0])
	if err != nil {
		t.Fatalf("create block: %v", err)
	}

	required := chain.RequiredApprovals(block)
	if required != 0 {
		t.Errorf("AddEnv should require 0 approvals, got %d", required)
	}
}

func TestApprovalStatusTracksProposerSeparately(t *testing.T) {
	chain, identities := createTestChainWithMembers(t, 3)
	proposer := identities[0]
	approver := identities[1]

	// Create a proposal
	member := Member{
		Name:         "newmember",
		SigningPub:   []byte("newsigpub"),
		MLKEMPub:     []byte("newmlkempub"),
		Role:         RoleMember,
		Environments: []string{"dev"},
		JoinedAt:     time.Now().UTC(),
	}

	head := chain.Head()
	block, err := NewBlock(head, ActionAddMember, member, proposer)
	if err != nil {
		t.Fatalf("create block: %v", err)
	}

	// Initial status
	status := chain.GetApprovalStatus(block)
	if status.Current != 0 {
		t.Errorf("Initial Current = %d, want 0", status.Current)
	}
	if status.Required != 2 { // 3 members, 50% threshold = 2
		t.Errorf("Required = %d, want 2", status.Required)
	}
	if len(status.Approvers) != 0 {
		t.Errorf("Initial Approvers count = %d, want 0", len(status.Approvers))
	}

	// Add valid approval
	block.AddApproval(approver)
	status = chain.GetApprovalStatus(block)
	if status.Current != 1 {
		t.Errorf("After approval Current = %d, want 1", status.Current)
	}
	if status.Remaining != 1 {
		t.Errorf("Remaining = %d, want 1", status.Remaining)
	}
	if len(status.Approvers) != 1 {
		t.Errorf("Approvers count = %d, want 1", len(status.Approvers))
	}
}

func TestCannotApproveAlreadyApproved(t *testing.T) {
	chain, identities := createTestChainWithMembers(t, 3)
	proposer := identities[0]
	approver := identities[1]

	// Create a proposal
	member := Member{
		Name:         "newmember",
		SigningPub:   []byte("newsigpub"),
		MLKEMPub:     []byte("newmlkempub"),
		Role:         RoleMember,
		Environments: []string{"dev"},
		JoinedAt:     time.Now().UTC(),
	}

	head := chain.Head()
	block, err := NewBlock(head, ActionAddMember, member, proposer)
	if err != nil {
		t.Fatalf("create block: %v", err)
	}

	// First approval should work
	err = chain.CanApprove(block, approver.SigningPublicKey())
	if err != nil {
		t.Errorf("First approval should work: %v", err)
	}

	// Add approval
	block.AddApproval(approver)

	// Second approval should fail
	err = chain.CanApprove(block, approver.SigningPublicKey())
	if err == nil {
		t.Error("Expected error for duplicate approval")
	}
	if err.Error() != "already approved this proposal" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestNonMemberCannotApprove(t *testing.T) {
	chain, identities := createTestChainWithMembers(t, 2)
	proposer := identities[0]

	// Create a non-member identity
	outsider, err := crypto.GenerateIdentity("outsider")
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	// Create a proposal
	member := Member{
		Name:         "newmember",
		SigningPub:   []byte("newsigpub"),
		MLKEMPub:     []byte("newmlkempub"),
		Role:         RoleMember,
		Environments: []string{"dev"},
		JoinedAt:     time.Now().UTC(),
	}

	head := chain.Head()
	block, err := NewBlock(head, ActionAddMember, member, proposer)
	if err != nil {
		t.Fatalf("create block: %v", err)
	}

	err = chain.CanApprove(block, outsider.SigningPublicKey())
	if err == nil {
		t.Error("Expected error for non-member approval")
	}
	if err.Error() != "approver is not a team member" {
		t.Errorf("Unexpected error: %v", err)
	}
}
