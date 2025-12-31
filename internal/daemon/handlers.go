package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"envctl.dev/go/envctl/internal/chain"
	"envctl.dev/go/envctl/internal/crypto"
	"envctl.dev/go/envctl/internal/protocol"
)

// Handlers contains all IPC method handlers
type Handlers struct {
	daemon *Daemon
}

// NewHandlers creates a new handlers instance
func NewHandlers(daemon *Daemon) *Handlers {
	return &Handlers{daemon: daemon}
}

// RegisterHandlers registers all handlers with the IPC server
func (h *Handlers) RegisterHandlers() {
	// Team handlers
	ipcHandlers["team.invite"] = h.handleTeamInvite
	ipcHandlers["team.pending"] = h.handleTeamPending
	ipcHandlers["team.approve"] = h.handleTeamApprove
	ipcHandlers["team.deny"] = h.handleTeamDeny
	ipcHandlers["team.access"] = h.handleTeamAccess
	ipcHandlers["team.grant"] = h.handleTeamGrant
	ipcHandlers["team.revoke"] = h.handleTeamRevoke
	ipcHandlers["team.leave"] = h.handleTeamLeave
	ipcHandlers["team.log"] = h.handleTeamLog

	// Env handlers
	ipcHandlers["env.analyze"] = h.handleEnvAnalyze
	ipcHandlers["env.use"] = h.handleEnvUse
	ipcHandlers["env.current"] = h.handleEnvCurrent
	ipcHandlers["env.notify"] = h.handleEnvNotify

	// Chain handlers
	ipcHandlers["chain.verify"] = h.handleChainVerify
	ipcHandlers["chain.repair"] = h.handleChainRepair
	ipcHandlers["chain.sync"] = h.handleChainSync

	// Config handlers
	ipcHandlers["config.get"] = h.handleConfigGet

	// Peer handlers
	ipcHandlers["peers.resolve"] = h.handlePeersResolve
	ipcHandlers["peers.info"] = h.handlePeersInfo

	// Lease handlers
	ipcHandlers["lease.grant"] = h.handleLeaseGrant
	ipcHandlers["lease.revoke"] = h.handleLeaseRevoke
	ipcHandlers["lease.extend"] = h.handleLeaseExtend
	ipcHandlers["lease.get"] = h.handleLeaseGet
	ipcHandlers["lease.list"] = h.handleLeaseList

	// Project handlers
	ipcHandlers["project.join"] = h.handleProjectJoin

	// Ops chain handlers
	ipcHandlers["opschain.status"] = h.handleOpsChainStatus
	ipcHandlers["opschain.pull"] = h.handleOpsChainPull
	ipcHandlers["opschain.push"] = h.handleOpsChainPush
}

// Team invite handler
func (h *Handlers) handleTeamInvite(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Team         string   `json:"team"`
		Pubkey       []byte   `json:"pubkey"`
		MLKEMPub     []byte   `json:"mlkem_pub"`
		Name         string   `json:"name"`
		Role         string   `json:"role"`
		Environments []string `json:"environments,omitempty"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// Get team chain
	teamChain := d.GetChain(req.Team)
	if teamChain == nil {
		return nil, fmt.Errorf("team not found: %s", req.Team)
	}

	// Check if current identity is admin
	if !teamChain.IsAdmin(d.identity.SigningPublicKey()) {
		return nil, fmt.Errorf("only admins can invite members")
	}

	// Check if the user is already a member
	if teamChain.IsMember(req.Pubkey) {
		return nil, fmt.Errorf("user is already a member of this team")
	}

	// Determine role
	role := chain.RoleMember
	if req.Role != "" {
		role = chain.Role(req.Role)
		if !role.Valid() {
			return nil, fmt.Errorf("invalid role: %s", req.Role)
		}
	}

	// Determine environments (use default if not specified)
	envs := req.Environments
	if len(envs) == 0 {
		policy := teamChain.Policy()
		if policy != nil {
			envs = policy.DefaultAccess
		}
	}

	// Create the new member
	member := chain.Member{
		Name:         req.Name,
		SigningPub:   req.Pubkey,
		MLKEMPub:     req.MLKEMPub,
		Role:         role,
		Environments: envs,
		JoinedAt:     time.Now().UTC(),
	}

	// Create the add_member block
	head := teamChain.Head()
	if head == nil {
		return nil, fmt.Errorf("chain has no head block")
	}

	block, err := chain.NewBlock(head, chain.ActionAddMember, member, d.identity)
	if err != nil {
		return nil, fmt.Errorf("create block: %w", err)
	}

	// Create the proposal (this will either commit immediately in bootstrap
	// phase or store as pending and broadcast to peers)
	if err := d.peerManager.CreateProposal(req.Team, block); err != nil {
		return nil, fmt.Errorf("create proposal: %w", err)
	}

	// Check if it was committed immediately
	if teamChain.IsMember(req.Pubkey) {
		return map[string]interface{}{
			"status":  "committed",
			"message": "member added (no approvals required)",
			"member":  req.Name,
			"role":    string(role),
		}, nil
	}

	// Return proposal info
	proposalID := fmt.Sprintf("%x", block.Hash)
	required := teamChain.RequiredApprovals(block)

	return map[string]interface{}{
		"status":      "pending",
		"message":     "invite proposal created, awaiting approvals",
		"proposal_id": proposalID,
		"member":      req.Name,
		"role":        string(role),
		"required":    required,
		"approvals":   0,
	}, nil
}

// Team pending handler
func (h *Handlers) handleTeamPending(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Team string `json:"team,omitempty"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		// No params is ok - return all pending
	}

	// Clean up expired proposals first (older than 72 hours)
	d.peerManager.CleanupExpiredProposals(72 * time.Hour)

	// Get pending proposals
	var proposals []*PendingProposal
	if req.Team != "" {
		proposals = d.peerManager.GetPendingProposals(req.Team)
	} else {
		proposals = d.peerManager.GetAllPendingProposals()
	}

	// Format response
	result := make([]map[string]interface{}, 0, len(proposals))
	for _, p := range proposals {
		teamChain := d.GetChain(p.Team)
		if teamChain == nil {
			continue
		}

		status := teamChain.GetApprovalStatus(p.Block)
		proposerName := "unknown"
		if member := teamChain.Member(p.Block.ProposedBy); member != nil {
			proposerName = member.Name
		}

		// Get subject description based on action
		var subject string
		switch p.Block.Action {
		case chain.ActionAddMember:
			if member, err := p.Block.GetMember(); err == nil {
				subject = fmt.Sprintf("Add member: %s (%s)", member.Name, member.Role)
			}
		case chain.ActionRemoveMember:
			if pubkey, err := p.Block.GetRemovedMember(); err == nil {
				if member := teamChain.Member(pubkey); member != nil {
					subject = fmt.Sprintf("Remove member: %s", member.Name)
				}
			}
		case chain.ActionChangeRole:
			if rc, err := p.Block.GetRoleChange(); err == nil {
				if member := teamChain.Member(rc.Member); member != nil {
					subject = fmt.Sprintf("Change role: %s -> %s", member.Name, rc.NewRole)
				}
			}
		case chain.ActionUpdateAccess:
			if ac, err := p.Block.GetAccessChange(); err == nil {
				if member := teamChain.Member(ac.Member); member != nil {
					subject = fmt.Sprintf("%s access for %s: %v", ac.Action, member.Name, ac.Environments)
				}
			}
		case chain.ActionDissolveTeam:
			subject = "Dissolve team"
		default:
			subject = string(p.Block.Action)
		}

		result = append(result, map[string]interface{}{
			"proposal_id":  fmt.Sprintf("%x", p.Block.Hash),
			"team":         p.Team,
			"action":       string(p.Block.Action),
			"subject":      subject,
			"proposed_by":  proposerName,
			"created_at":   p.ReceivedAt,
			"block_index":  p.Block.Index,
			"approvals":    status.Current,
			"required":     status.Required,
			"remaining":    status.Remaining,
			"approvers":    status.Approvers,
			"can_approve":  teamChain.CanApprove(p.Block, d.identity.SigningPublicKey()) == nil,
		})
	}

	return result, nil
}

// Team approve handler
func (h *Handlers) handleTeamApprove(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Team       string `json:"team"`
		ProposalID string `json:"proposal_id"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// Get the pending proposal
	proposal := d.peerManager.GetProposal(req.ProposalID)
	if proposal == nil {
		return nil, fmt.Errorf("proposal not found: %s", req.ProposalID)
	}

	// Verify team matches if specified
	if req.Team != "" && proposal.Team != req.Team {
		return nil, fmt.Errorf("proposal is for team %s, not %s", proposal.Team, req.Team)
	}

	// Get the chain
	teamChain := d.GetChain(proposal.Team)
	if teamChain == nil {
		return nil, fmt.Errorf("team not found: %s", proposal.Team)
	}

	// Check if we can approve
	if err := teamChain.CanApprove(proposal.Block, d.identity.SigningPublicKey()); err != nil {
		return nil, err
	}

	// Create the approval
	approval := chain.Approval{
		By:        d.identity.SigningPublicKey(),
		SigAlgo:   "ed25519",
		Signature: d.identity.Sign(proposal.Block.Hash),
		Timestamp: time.Now().UTC(),
	}

	// Submit the approval
	if err := d.peerManager.ApproveProposal(req.ProposalID, &approval); err != nil {
		return nil, fmt.Errorf("approve proposal: %w", err)
	}

	// Get updated status
	status := teamChain.GetApprovalStatus(proposal.Block)

	return map[string]interface{}{
		"status":    "approved",
		"team":      proposal.Team,
		"action":    string(proposal.Block.Action),
		"approvals": status.Current,
		"required":  status.Required,
		"remaining": status.Remaining,
		"committed": status.Complete,
	}, nil
}

// Team deny handler - removes a pending proposal
func (h *Handlers) handleTeamDeny(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Team       string `json:"team"`
		ProposalID string `json:"proposal_id"`
		Reason     string `json:"reason,omitempty"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// Get the pending proposal
	proposal := d.peerManager.GetProposal(req.ProposalID)
	if proposal == nil {
		return nil, fmt.Errorf("proposal not found: %s", req.ProposalID)
	}

	// Verify team matches if specified
	if req.Team != "" && proposal.Team != req.Team {
		return nil, fmt.Errorf("proposal is for team %s, not %s", proposal.Team, req.Team)
	}

	// Get the chain
	teamChain := d.GetChain(proposal.Team)
	if teamChain == nil {
		return nil, fmt.Errorf("team not found: %s", proposal.Team)
	}

	// Check if the user is a member (only members can deny)
	if !teamChain.IsMember(d.identity.SigningPublicKey()) {
		return nil, fmt.Errorf("only team members can deny proposals")
	}

	// Remove the proposal from pending
	d.peerManager.proposalStore.Remove(req.ProposalID)

	// Broadcast denial event to IPC clients
	d.BroadcastEvent(&Event{
		Event: "chain.proposal_denied",
		Payload: mustMarshal(map[string]any{
			"team":        proposal.Team,
			"proposal_id": req.ProposalID,
			"action":      string(proposal.Block.Action),
			"reason":      req.Reason,
		}),
	})

	return map[string]interface{}{
		"status":      "denied",
		"team":        proposal.Team,
		"proposal_id": req.ProposalID,
		"action":      string(proposal.Block.Action),
		"reason":      req.Reason,
	}, nil
}

// Team access handler
func (h *Handlers) handleTeamAccess(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Team   string `json:"team"`
		Member string `json:"member"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	teamChain := d.GetChain(req.Team)
	if teamChain == nil {
		return nil, fmt.Errorf("team not found: %s", req.Team)
	}

	member := teamChain.FindMemberByName(req.Member)
	if member == nil {
		return nil, fmt.Errorf("member not found: %s", req.Member)
	}

	return map[string]interface{}{
		"environments": member.Environments,
		"role":         member.Role,
	}, nil
}

// Team grant handler
func (h *Handlers) handleTeamGrant(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Team         string   `json:"team"`
		Member       string   `json:"member"`
		Environments []string `json:"environments"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	return map[string]string{"status": "pending", "message": "access grant proposal created"}, nil
}

// Team revoke handler
func (h *Handlers) handleTeamRevoke(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Team         string   `json:"team"`
		Member       string   `json:"member"`
		Environments []string `json:"environments"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	return map[string]string{"status": "pending", "message": "access revoke proposal created"}, nil
}

// Team leave handler
func (h *Handlers) handleTeamLeave(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Team string `json:"team"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	return map[string]string{"status": "left"}, nil
}

// Team log handler
func (h *Handlers) handleTeamLog(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Team  string `json:"team"`
		Limit int    `json:"limit,omitempty"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	teamChain := d.GetChain(req.Team)
	if teamChain == nil {
		return nil, fmt.Errorf("team not found: %s", req.Team)
	}

	limit := req.Limit
	if limit == 0 {
		limit = 50
	}

	blocks := teamChain.Blocks(0)
	if len(blocks) > limit {
		blocks = blocks[len(blocks)-limit:]
	}

	entries := make([]map[string]interface{}, len(blocks))
	for i, block := range blocks {
		entries[i] = map[string]interface{}{
			"index":     block.Index,
			"action":    block.Action,
			"timestamp": block.Timestamp,
		}
	}

	return entries, nil
}


// Env analyze handler
func (h *Handlers) handleEnvAnalyze(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	return map[string]interface{}{
		"path":      req.Path,
		"var_count": 0,
		"sensitive": []string{},
	}, nil
}

// Env use handler
func (h *Handlers) handleEnvUse(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	return map[string]string{"current": req.Name}, nil
}

// Env current handler
func (h *Handlers) handleEnvCurrent(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	return map[string]string{"name": "dev"}, nil
}

// Env notify handler - notifies peers that an env has been updated
func (h *Handlers) handleEnvNotify(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Team string `json:"team"`
		Env  string `json:"env"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// Check if we're a member of the team with access
	teamChain := d.GetChain(req.Team)
	if teamChain == nil {
		return nil, fmt.Errorf("team not found: %s", req.Team)
	}

	if !teamChain.HasEnvAccess(d.identity.SigningPublicKey(), req.Env) {
		return nil, fmt.Errorf("no access to environment: %s", req.Env)
	}

	// Create update notification
	update := protocol.EnvUpdated{
		Team:      req.Team,
		Env:       req.Env,
		UpdatedBy: d.identity.SigningPublicKey(),
		Timestamp: time.Now(),
	}

	msg, err := protocol.NewMessage(protocol.MsgEnvUpdated, update)
	if err != nil {
		return nil, fmt.Errorf("create message: %w", err)
	}

	// Broadcast to all peers in this team
	d.peerManager.BroadcastToTeam(req.Team, msg)

	peerCount := d.peerManager.PeerCount()
	return map[string]interface{}{
		"team":     req.Team,
		"env":      req.Env,
		"notified": peerCount,
	}, nil
}

// Chain verify handler
func (h *Handlers) handleChainVerify(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Team string `json:"team,omitempty"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		// No params is ok, verify all
	}

	teams := d.Teams()
	if req.Team != "" {
		teams = []string{req.Team}
	}

	for _, teamName := range teams {
		teamChain := d.GetChain(teamName)
		if teamChain == nil {
			continue
		}

		if err := teamChain.Verify(); err != nil {
			return map[string]interface{}{
				"team":        teamName,
				"valid":       false,
				"block_count": teamChain.Len(),
				"error":       err.Error(),
			}, nil
		}
	}

	if len(teams) == 1 {
		teamChain := d.GetChain(teams[0])
		return map[string]interface{}{
			"team":        teams[0],
			"valid":       true,
			"block_count": teamChain.Len(),
		}, nil
	}

	return map[string]interface{}{
		"valid":       true,
		"teams_count": len(teams),
	}, nil
}

// Chain repair handler
func (h *Handlers) handleChainRepair(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Team string `json:"team,omitempty"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		// No params is ok
	}

	// Try to repair from backup first
	if req.Team != "" {
		chainPath := d.paths.ChainFile(req.Team)
		c, recovered, err := chain.TryLoadWithRecovery(chainPath)
		if err != nil {
			return map[string]interface{}{
				"team":     req.Team,
				"repaired": false,
				"error":    err.Error(),
			}, nil
		}

		if recovered {
			d.mu.Lock()
			d.chains[req.Team] = c
			d.mu.Unlock()

			return map[string]interface{}{
				"team":        req.Team,
				"repaired":    true,
				"source":      "backup",
				"blocks_added": c.Len(),
			}, nil
		}
	}

	return map[string]interface{}{
		"repaired": false,
		"error":    "no repair needed or no backup available",
	}, nil
}

// Chain sync handler - requests chain updates from peers
func (h *Handlers) handleChainSync(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Team string `json:"team"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if req.Team == "" {
		return nil, fmt.Errorf("team is required")
	}

	teamChain := d.GetChain(req.Team)
	if teamChain == nil {
		return nil, fmt.Errorf("team not found: %s", req.Team)
	}

	blocksBefore := teamChain.Len()

	// Broadcast chain head to all peers in this team
	head := teamChain.Head()
	if head == nil {
		return nil, fmt.Errorf("chain has no head")
	}

	chainHead := protocol.ChainHead{
		Team:  req.Team,
		Index: head.Index,
		Hash:  head.Hash,
	}

	msg, err := protocol.NewMessage(protocol.MsgChainHead, chainHead)
	if err != nil {
		return nil, fmt.Errorf("create message: %w", err)
	}

	// Broadcast to trigger sync from peers who have more blocks
	d.peerManager.BroadcastToTeam(req.Team, msg)

	// Return current state - the actual sync happens asynchronously
	return map[string]interface{}{
		"status":        "sync_requested",
		"blocks_before": blocksBefore,
		"blocks_after":  blocksBefore, // Will be updated async
		"blocks_added":  0,
	}, nil
}

// Config get handler
func (h *Handlers) handleConfigGet(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	return map[string]interface{}{
		"web_port": 7835,
		"p2p_port": 7834,
	}, nil
}

// Peers resolve handler
func (h *Handlers) handlePeersResolve(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Name string `json:"name"`
		Team string `json:"team,omitempty"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	peers := d.peerManager.Peers()
	for _, peer := range peers {
		if peer.Name == req.Name {
			return map[string]interface{}{
				"name":      peer.Name,
				"connected": peer.Connected,
				"teams":     peer.Teams,
			}, nil
		}
	}

	return nil, fmt.Errorf("peer not found: %s", req.Name)
}

// Peers info handler - returns detailed peer info including public keys
func (h *Handlers) handlePeersInfo(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Name        string `json:"name"`
		Fingerprint string `json:"fingerprint,omitempty"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// Get peer from peer manager
	peer := d.peerManager.GetPeerByName(req.Name)
	if peer == nil && req.Fingerprint != "" {
		peer = d.peerManager.GetPeer(req.Fingerprint)
	}

	if peer == nil {
		return nil, fmt.Errorf("peer not found: %s", req.Name)
	}

	if peer.State != PeerStateConnected {
		return nil, fmt.Errorf("peer not connected: %s", req.Name)
	}

	// Get handshake info which contains the public keys
	peer.mu.RLock()
	handshake := peer.handshake
	peer.mu.RUnlock()

	if handshake == nil {
		return nil, fmt.Errorf("peer handshake not available: %s", req.Name)
	}

	return map[string]interface{}{
		"name":        peer.Name,
		"fingerprint": peer.Fingerprint,
		"connected":   true,
		"teams":       peer.Teams,
		"pubkey":      handshake.Pubkey,
		"mlkem_pub":   handshake.MLKEMPub,
	}, nil
}

// Lease grant handler - creates a new lease with TTL
func (h *Handlers) handleLeaseGrant(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		ProjectDir  string  `json:"project_dir"`
		ProjectName string  `json:"project_name"`
		Environment string  `json:"environment"`
		DotEnvPath  string  `json:"dotenv_path"`
		TTLSeconds  float64 `json:"ttl_seconds"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if req.ProjectDir == "" || req.Environment == "" {
		return nil, fmt.Errorf("project_dir and environment are required")
	}

	if req.TTLSeconds <= 0 {
		return nil, fmt.Errorf("ttl_seconds must be positive")
	}

	ttl := time.Duration(req.TTLSeconds) * time.Second
	lease, err := d.leaseManager.Grant(req.ProjectDir, req.ProjectName, req.Environment, req.DotEnvPath, ttl)
	if err != nil {
		return nil, err
	}

	return lease, nil
}

// Lease revoke handler - immediately revokes a lease
func (h *Handlers) handleLeaseRevoke(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		ProjectDir  string `json:"project_dir"`
		Environment string `json:"environment"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if req.ProjectDir == "" || req.Environment == "" {
		return nil, fmt.Errorf("project_dir and environment are required")
	}

	if err := d.leaseManager.Revoke(req.ProjectDir, req.Environment); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"status":      "revoked",
		"project_dir": req.ProjectDir,
		"environment": req.Environment,
	}, nil
}

// Lease extend handler - extends an existing lease
func (h *Handlers) handleLeaseExtend(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		ProjectDir    string  `json:"project_dir"`
		Environment   string  `json:"environment"`
		ExtendSeconds float64 `json:"extend_seconds"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if req.ProjectDir == "" || req.Environment == "" {
		return nil, fmt.Errorf("project_dir and environment are required")
	}

	if req.ExtendSeconds <= 0 {
		return nil, fmt.Errorf("extend_seconds must be positive")
	}

	extension := time.Duration(req.ExtendSeconds) * time.Second
	lease, err := d.leaseManager.Extend(req.ProjectDir, req.Environment, extension)
	if err != nil {
		return nil, err
	}

	return lease, nil
}

// Lease get handler - gets an active lease
func (h *Handlers) handleLeaseGet(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		ProjectDir  string `json:"project_dir"`
		Environment string `json:"environment"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if req.ProjectDir == "" || req.Environment == "" {
		return nil, fmt.Errorf("project_dir and environment are required")
	}

	lease := d.leaseManager.Get(req.ProjectDir, req.Environment)
	if lease == nil {
		return nil, fmt.Errorf("no active lease for %s:%s", req.ProjectDir, req.Environment)
	}

	return lease, nil
}

// Lease list handler - lists all active leases
func (h *Handlers) handleLeaseList(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	leases := d.leaseManager.List()
	return leases, nil
}

// Project join handler - joins a project using an invite code
func (h *Handlers) handleProjectJoin(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Code       string `json:"code"`
		SigningPub []byte `json:"signing_pub"`
		MLKEMPub   []byte `json:"mlkem_pub"`
		Name       string `json:"name"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if req.Code == "" {
		return nil, fmt.Errorf("invite code is required")
	}

	// Normalize the invite code
	code := chain.NormalizeInviteCode(req.Code)

	// Compute the pubkey hash to match against invites
	pubkeyHash := crypto.HashPublicKey(req.SigningPub)

	// First, check if we already have a chain with this invite
	for _, teamName := range d.Teams() {
		teamChain := d.GetChain(teamName)
		if teamChain == nil {
			continue
		}

		// Try to validate the invite
		invite, err := teamChain.ValidateInvite(code, req.SigningPub)
		if err != nil {
			continue // Not a match, try next chain
		}

		// Found a matching invite! Create the member-add block
		member := chain.Member{
			Name:         req.Name,
			SigningPub:   req.SigningPub,
			MLKEMPub:     req.MLKEMPub,
			Role:         invite.Role,
			Environments: invite.Environments,
			JoinedAt:     time.Now().UTC(),
			InviteCode:   code, // Link to the invite
		}

		// Create the add_member block (signed by us as the admin)
		head := teamChain.Head()
		if head == nil {
			return nil, fmt.Errorf("chain has no head block")
		}

		block, err := chain.NewBlock(head, chain.ActionAddMember, member, d.identity)
		if err != nil {
			return nil, fmt.Errorf("create block: %w", err)
		}

		// For solo mode or bootstrap, commit directly
		// Otherwise, create a proposal that needs approvals
		policy := teamChain.Policy()
		if policy != nil && policy.SoloMode {
			// Commit directly in solo mode
			if err := teamChain.AppendBlock(block); err != nil {
				return nil, fmt.Errorf("append block: %w", err)
			}

			// Save the chain
			chainPath := d.paths.ChainFile(teamName)
			if err := teamChain.Save(chainPath); err != nil {
				return nil, fmt.Errorf("save chain: %w", err)
			}

			return map[string]interface{}{
				"success":      true,
				"project_name": teamName,
				"chain_path":   chainPath,
			}, nil
		}

		// Create the proposal (this will broadcast to peers)
		if err := d.peerManager.CreateProposal(teamName, block); err != nil {
			return nil, fmt.Errorf("create proposal: %w", err)
		}

		// Check if it was committed immediately (bootstrap phase)
		if teamChain.IsMember(req.SigningPub) {
			chainPath := d.paths.ChainFile(teamName)
			return map[string]interface{}{
				"success":      true,
				"project_name": teamName,
				"chain_path":   chainPath,
			}, nil
		}

		// Return pending status
		return map[string]interface{}{
			"success": false,
			"error":   "join proposal created, awaiting approval from team members",
		}, nil
	}

	// No local chain has this invite - broadcast request to peers
	// The flow is:
	// 1. We send MsgChainRequest to peers
	// 2. A peer responds with MsgChainResponse containing the chain
	// 3. handleChainResponse stores the chain and sends MsgJoinRequest
	// 4. The peer validates and responds with MsgJoinApproved containing the add_member block
	// 5. handleJoinApproved appends the block, making us a member

	requestID := uuid.New().String()
	chainReq := protocol.ChainRequest{
		RequestID:  requestID,
		InviteCode: code,
		PubKeyHash: pubkeyHash,
	}

	// Store the pending join info so handleChainResponse can send the join request
	d.peerManager.StorePendingJoin(requestID, code, req.Name, req.SigningPub, req.MLKEMPub)
	defer d.peerManager.ClearPendingJoin(requestID)

	msg, err := protocol.NewMessage(protocol.MsgChainRequest, chainReq)
	if err != nil {
		return nil, fmt.Errorf("create message: %w", err)
	}

	// Broadcast to all connected peers
	d.peerManager.Broadcast(msg)

	// Wait for the join to complete (we should become a member)
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			return map[string]interface{}{
				"success": false,
				"error":   "timeout waiting for join approval from peers. Ensure at least one team member is online.",
			}, nil
		case <-ticker.C:
			// Check if we're now a member of any team
			for _, teamName := range d.Teams() {
				teamChain := d.GetChain(teamName)
				if teamChain == nil {
					continue
				}

				// Check if we're a member now (the join was approved)
				if teamChain.IsMember(req.SigningPub) {
					chainPath := d.paths.ChainFile(teamName)
					return map[string]interface{}{
						"success":      true,
						"project_name": teamName,
						"chain_path":   chainPath,
					}, nil
				}
			}
		}
	}
}

// Ops chain status handler
func (h *Handlers) handleOpsChainStatus(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Project     string `json:"project"`
		Environment string `json:"environment"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if req.Project == "" {
		return nil, fmt.Errorf("project is required")
	}
	if req.Environment == "" {
		req.Environment = "dev"
	}

	// Get ops chain head info from local storage
	chainPath := d.paths.OpsChainFile(req.Project, req.Environment)

	// Check if chain exists
	if _, err := os.Stat(chainPath); os.IsNotExist(err) {
		return map[string]interface{}{
			"project":     req.Project,
			"environment": req.Environment,
			"exists":      false,
			"op_count":    0,
		}, nil
	}

	// Load chain head info (we don't need identity to read head info)
	// For now, return basic file info
	info, err := os.Stat(chainPath)
	if err != nil {
		return nil, fmt.Errorf("stat chain file: %w", err)
	}

	return map[string]interface{}{
		"project":     req.Project,
		"environment": req.Environment,
		"exists":      true,
		"modified_at": info.ModTime(),
	}, nil
}

// Ops chain pull handler - pulls ops from peers
func (h *Handlers) handleOpsChainPull(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Project     string `json:"project"`
		Environment string `json:"environment"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if req.Project == "" {
		return nil, fmt.Errorf("project is required")
	}
	if req.Environment == "" {
		req.Environment = "dev"
	}

	// Get current ops chain state before pull
	mgr := d.GetOpsChainManager()
	initialSeq := uint64(0)
	if chain, err := mgr.LoadChain(req.Project, req.Environment); err == nil {
		initialSeq = chain.NextSeq()
	}

	// Find peers who are members of this project
	peers := d.peerManager.GetProjectPeers(req.Project)
	if len(peers) == 0 {
		return map[string]interface{}{
			"success": false,
			"error":   "no connected peers for this project",
		}, nil
	}

	// Send ops request to first available peer
	requestID := uuid.New().String()
	opsReq := protocol.OpsGetOps{
		RequestID:   requestID,
		Project:     req.Project,
		Environment: req.Environment,
		FromSeq:     initialSeq, // Request ops from current seq
	}

	msg, err := protocol.NewMessage(protocol.MsgOpsGetOps, opsReq)
	if err != nil {
		return nil, fmt.Errorf("create message: %w", err)
	}
	msg.Sign(d.identity.SigningPrivateKey())

	// Send to first peer
	if err := d.peerManager.Send(peers[0], msg); err != nil {
		return nil, fmt.Errorf("send message: %w", err)
	}

	// Wait for response by polling the local chain
	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			// Check if we got any new ops
			if chain, err := mgr.LoadChain(req.Project, req.Environment); err == nil {
				newSeq := chain.NextSeq()
				if newSeq > initialSeq {
					return map[string]interface{}{
						"success":      true,
						"ops_received": int(newSeq - initialSeq),
						"status":       "synced",
					}, nil
				}
			}
			return map[string]interface{}{
				"success": true,
				"status":  "up_to_date",
				"message": "no new operations from peer",
			}, nil
		case <-ticker.C:
			// Check if local chain has new ops
			if chain, err := mgr.LoadChain(req.Project, req.Environment); err == nil {
				newSeq := chain.NextSeq()
				if newSeq > initialSeq {
					return map[string]interface{}{
						"success":      true,
						"ops_received": int(newSeq - initialSeq),
						"status":       "synced",
					}, nil
				}
			}
		}
	}
}

// Ops chain push handler - pushes ops to peers
func (h *Handlers) handleOpsChainPush(ctx context.Context, d *Daemon, client *IPCClient, params json.RawMessage) (interface{}, error) {
	var req struct {
		Project     string   `json:"project"`
		Environment string   `json:"environment"`
		Operations  []protocol.OpsOperation `json:"operations"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if req.Project == "" {
		return nil, fmt.Errorf("project is required")
	}
	if req.Environment == "" {
		req.Environment = "dev"
	}
	if len(req.Operations) == 0 {
		return nil, fmt.Errorf("no operations to push")
	}

	// Find peers who are members of this project
	peers := d.peerManager.GetProjectPeers(req.Project)
	if len(peers) == 0 {
		return map[string]interface{}{
			"success": false,
			"error":   "no connected peers for this project",
		}, nil
	}

	// Create push message
	requestID := uuid.New().String()
	opsPush := protocol.OpsPush{
		RequestID:   requestID,
		Project:     req.Project,
		Environment: req.Environment,
		Operations:  req.Operations,
	}

	msg, err := protocol.NewMessage(protocol.MsgOpsPush, opsPush)
	if err != nil {
		return nil, fmt.Errorf("create message: %w", err)
	}
	msg.Sign(d.identity.SigningPrivateKey())

	// Broadcast to all project peers
	sent := 0
	for _, peer := range peers {
		if err := d.peerManager.Send(peer, msg); err != nil {
			continue
		}
		sent++
	}

	return map[string]interface{}{
		"success":    true,
		"request_id": requestID,
		"sent_to":    sent,
		"total_ops":  len(req.Operations),
	}, nil
}
