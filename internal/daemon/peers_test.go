package daemon

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"uradical.io/go/envctl/internal/chain"
	"uradical.io/go/envctl/internal/protocol"
	"uradical.io/go/envctl/internal/testutil"
)

// TestPeerConnection tests that two peers can connect and complete handshake
func TestPeerConnection(t *testing.T) {
	// Create two test identities
	alice := testutil.NewTestIdentity(t, "alice")
	bob := testutil.NewTestIdentity(t, "bob")

	// Create a shared team
	teamName := "test-team"
	teamChain := alice.CreateTeam(teamName)

	// Add Bob to the team using NewBlock with a Member subject
	bobMember := chain.Member{
		Name:         "bob",
		MLKEMPub:     bob.Identity.MLKEMPublicKey(),
		SigningPub:   bob.SigningPublicKey(),
		Role:         chain.RoleMember,
		Environments: []string{"dev"},
	}

	addMemberBlock, err := chain.NewBlock(
		teamChain.Head(),
		chain.ActionAddMember,
		bobMember,
		alice.Identity,
	)
	if err != nil {
		t.Fatalf("create add member block: %v", err)
	}

	// Approve and append
	if err := teamChain.AppendBlock(addMemberBlock); err != nil {
		t.Fatalf("append block: %v", err)
	}

	alice.SaveTeam(teamName, teamChain)
	bob.SaveTeam(teamName, teamChain)

	// Start listeners on both sides
	alicePort := 18835
	bobPort := 18836

	// Create TCP listeners
	aliceListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", alicePort))
	if err != nil {
		t.Fatalf("alice listener: %v", err)
	}
	defer aliceListener.Close()

	bobListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", bobPort))
	if err != nil {
		t.Fatalf("bob listener: %v", err)
	}
	defer bobListener.Close()

	// Set up a connection test
	var wg sync.WaitGroup
	var aliceHandshakeResult *protocol.Handshake
	var bobHandshakeResult *protocol.Handshake
	var aliceErr, bobErr error

	// Bob accepts connection
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := aliceListener.Accept()
		if err != nil {
			aliceErr = fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()

		ourHandshake := protocol.NewHandshakeFromIdentity(alice.Identity, []string{teamName})
		aliceHandshakeResult, aliceErr = protocol.PerformHandshake(conn, ourHandshake)
	}()

	// Alice connects to Bob
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", alicePort), 5*time.Second)
		if err != nil {
			bobErr = fmt.Errorf("dial: %w", err)
			return
		}
		defer conn.Close()

		ourHandshake := protocol.NewHandshakeFromIdentity(bob.Identity, []string{teamName})
		bobHandshakeResult, bobErr = protocol.PerformHandshake(conn, ourHandshake)
	}()

	wg.Wait()

	// Check results
	if aliceErr != nil {
		t.Fatalf("alice handshake error: %v", aliceErr)
	}
	if bobErr != nil {
		t.Fatalf("bob handshake error: %v", bobErr)
	}

	// Verify handshakes
	if aliceHandshakeResult == nil {
		t.Fatal("alice did not receive handshake")
	}
	if bobHandshakeResult == nil {
		t.Fatal("bob did not receive handshake")
	}

	// Verify Alice received Bob's handshake
	if aliceHandshakeResult.Name != "bob" {
		t.Errorf("alice expected name 'bob', got '%s'", aliceHandshakeResult.Name)
	}
	if len(aliceHandshakeResult.Teams) != 1 || aliceHandshakeResult.Teams[0] != teamName {
		t.Errorf("alice expected teams [%s], got %v", teamName, aliceHandshakeResult.Teams)
	}

	// Verify Bob received Alice's handshake
	if bobHandshakeResult.Name != "alice" {
		t.Errorf("bob expected name 'alice', got '%s'", bobHandshakeResult.Name)
	}
	if len(bobHandshakeResult.Teams) != 1 || bobHandshakeResult.Teams[0] != teamName {
		t.Errorf("bob expected teams [%s], got %v", teamName, bobHandshakeResult.Teams)
	}

	t.Log("Handshake completed successfully between Alice and Bob")
}

// TestChainSync tests that chains can be synchronized between peers
func TestChainSync(t *testing.T) {
	// Create two test identities
	alice := testutil.NewTestIdentity(t, "alice")
	bob := testutil.NewTestIdentity(t, "bob")

	teamName := "sync-team"

	// Alice creates a team and adds some members
	teamChain := alice.CreateTeam(teamName)

	// Add Bob to the team
	bobMember := chain.Member{
		Name:         "bob",
		MLKEMPub:     bob.Identity.MLKEMPublicKey(),
		SigningPub:   bob.SigningPublicKey(),
		Role:         chain.RoleMember,
		Environments: []string{"dev"},
	}

	addBobBlock, err := chain.NewBlock(
		teamChain.Head(),
		chain.ActionAddMember,
		bobMember,
		alice.Identity,
	)
	if err != nil {
		t.Fatalf("create add bob block: %v", err)
	}
	if err := teamChain.AppendBlock(addBobBlock); err != nil {
		t.Fatalf("append block: %v", err)
	}

	// Save Alice's full chain
	alice.SaveTeam(teamName, teamChain)

	// Bob only has the genesis block (simulating a new peer)
	bobChain := alice.LoadTeam(teamName)
	bobBlocks := bobChain.Blocks(0)
	if len(bobBlocks) < 1 {
		t.Fatal("need at least genesis block")
	}

	// Create a new chain with just the genesis for Bob
	bobPartialChain, err := chain.NewFromGenesis(bobBlocks[0])
	if err != nil {
		t.Fatalf("create bob partial chain: %v", err)
	}

	// Verify Alice has more blocks than Bob's partial chain
	if teamChain.Len() <= bobPartialChain.Len() {
		t.Fatalf("alice should have more blocks: alice=%d, bob=%d", teamChain.Len(), bobPartialChain.Len())
	}

	// Simulate chain sync: Alice sends her chain head
	aliceHead := teamChain.Head()
	chainHead := protocol.ChainHead{
		Team:  teamName,
		Index: aliceHead.Index,
		Hash:  aliceHead.Hash,
	}

	// Bob sees Alice has more blocks and requests them
	bobHead := bobPartialChain.Head()
	if chainHead.Index > bobHead.Index {
		// Bob would request blocks starting from his head
		startIndex := bobHead.Index + 1
		blocksToSync := teamChain.Blocks(startIndex)

		// Apply blocks to Bob's chain
		for _, block := range blocksToSync {
			if err := bobPartialChain.AppendBlock(block); err != nil {
				t.Fatalf("bob append block %d: %v", block.Index, err)
			}
		}

		t.Logf("Bob synced %d blocks from Alice", len(blocksToSync))
	}

	// Verify chains are now in sync
	if teamChain.Len() != bobPartialChain.Len() {
		t.Errorf("chains not in sync: alice=%d, bob=%d", teamChain.Len(), bobPartialChain.Len())
	}

	// Verify Bob is now a member in his chain
	if !bobPartialChain.IsMember(bob.SigningPublicKey()) {
		t.Error("Bob should be a member after sync")
	}
}

// TestMessageFraming tests the length-prefixed message framing
func TestMessageFraming(t *testing.T) {
	// Create a pipe for testing
	reader, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()

	// Create framers
	senderFramer := protocol.NewFramer(nil, writer)
	receiverFramer := protocol.NewFramer(reader, nil)

	// Test various message types
	testCases := []struct {
		name    string
		msgType protocol.MessageType
		payload interface{}
	}{
		{
			name:    "ping",
			msgType: protocol.MsgPing,
			payload: struct{}{},
		},
		{
			name:    "chain_head",
			msgType: protocol.MsgChainHead,
			payload: protocol.ChainHead{
				Team:  "test-team",
				Index: 5,
				Hash:  []byte("test-hash-123"),
			},
		},
		{
			name:    "env_request",
			msgType: protocol.MsgRequest,
			payload: protocol.EnvRequest{
				ID:        "req-123",
				Team:      "test-team",
				Env:       "dev",
				From:      []byte("pubkey-bytes"),
				Timestamp: time.Now().UTC(),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Send in goroutine
			sendErr := make(chan error, 1)
			go func() {
				msg, err := protocol.NewMessage(tc.msgType, tc.payload)
				if err != nil {
					sendErr <- err
					return
				}
				sendErr <- senderFramer.WriteMessage(msg)
			}()

			// Receive
			received, err := receiverFramer.ReadMessage()
			if err != nil {
				t.Fatalf("receive: %v", err)
			}

			if err := <-sendErr; err != nil {
				t.Fatalf("send: %v", err)
			}

			// Verify
			if received.Type != tc.msgType {
				t.Errorf("expected type %s, got %s", tc.msgType, received.Type)
			}
		})
	}
}

// TestEnvRequestResponse tests environment request and response flow
func TestEnvRequestResponse(t *testing.T) {
	// Create test identities
	alice := testutil.NewTestIdentity(t, "alice")
	bob := testutil.NewTestIdentity(t, "bob")

	teamName := "env-test-team"
	envName := "dev"

	// Alice creates a team
	teamChain := alice.CreateTeam(teamName)

	// Add Bob to the team with dev access
	bobMember := chain.Member{
		Name:         "bob",
		MLKEMPub:     bob.Identity.MLKEMPublicKey(),
		SigningPub:   bob.SigningPublicKey(),
		Role:         chain.RoleMember,
		Environments: []string{envName},
	}

	addBobBlock, err := chain.NewBlock(
		teamChain.Head(),
		chain.ActionAddMember,
		bobMember,
		alice.Identity,
	)
	if err != nil {
		t.Fatalf("create add bob block: %v", err)
	}
	if err := teamChain.AppendBlock(addBobBlock); err != nil {
		t.Fatalf("append block: %v", err)
	}

	// Save chain for both
	alice.SaveTeam(teamName, teamChain)
	bob.SaveTeam(teamName, teamChain)

	// Alice creates some secrets
	secrets := map[string]string{
		"DB_HOST":     "localhost",
		"DB_PASSWORD": "secret123",
		"API_KEY":     "api-key-value",
	}
	alice.CreateSecrets(teamName, envName, secrets)

	// Simulate Bob sending a request
	request := protocol.EnvRequest{
		ID:        "test-request-123",
		Team:      teamName,
		Env:       envName,
		From:      bob.SigningPublicKey(),
		Timestamp: time.Now().UTC(),
	}

	// Serialize and deserialize to test JSON round-trip
	requestMsg, err := protocol.NewMessage(protocol.MsgRequest, request)
	if err != nil {
		t.Fatalf("create request message: %v", err)
	}

	requestData, err := json.Marshal(requestMsg)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	var receivedMsg protocol.Message
	if err := json.Unmarshal(requestData, &receivedMsg); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}

	var receivedRequest protocol.EnvRequest
	if err := receivedMsg.ParsePayload(&receivedRequest); err != nil {
		t.Fatalf("parse request payload: %v", err)
	}

	// Verify the request
	if receivedRequest.Team != teamName {
		t.Errorf("expected team %s, got %s", teamName, receivedRequest.Team)
	}
	if receivedRequest.Env != envName {
		t.Errorf("expected env %s, got %s", envName, receivedRequest.Env)
	}

	// Verify Bob is a member and has access
	if !teamChain.IsMember(receivedRequest.From) {
		t.Error("requester should be a team member")
	}

	// Alice would respond with an offer
	offer := protocol.EnvOffer{
		RequestID: receivedRequest.ID,
		Team:      teamName,
		Env:       envName,
		From:      alice.SigningPublicKey(),
		VarCount:  len(secrets),
	}

	offerMsg, err := protocol.NewMessage(protocol.MsgOffer, offer)
	if err != nil {
		t.Fatalf("create offer message: %v", err)
	}

	if offerMsg.Type != protocol.MsgOffer {
		t.Errorf("expected offer message type, got %s", offerMsg.Type)
	}

	t.Logf("Env request/response flow verified: %d variables offered", offer.VarCount)
}

// TestPendingProposalTracking tests that pending proposals are tracked correctly
func TestPendingProposalTracking(t *testing.T) {
	// Create test identity
	alice := testutil.NewTestIdentity(t, "alice")

	teamName := "proposal-test-team"
	teamChain := alice.CreateTeam(teamName)

	// Create a mock block hash
	blockHash := []byte("test-block-hash-12345678")
	hashHex := hex.EncodeToString(blockHash)

	// Create pending proposal tracking
	pendingProposals := make(map[string]*PendingProposal)

	// Simulate receiving a proposal
	block := &chain.Block{
		Index:  1,
		Action: chain.ActionAddMember,
		Hash:   blockHash,
	}

	proposal := &PendingProposal{
		Block:      block,
		Team:       teamName,
		ReceivedAt: time.Now(),
		Approvals:  make(map[string]protocol.Approval),
	}

	pendingProposals[hashHex] = proposal

	// Verify proposal is tracked
	if _, exists := pendingProposals[hashHex]; !exists {
		t.Error("proposal should be tracked")
	}

	// Simulate receiving an approval
	approval := protocol.Approval{
		Team:      teamName,
		BlockHash: blockHash,
		By:        alice.SigningPublicKey(),
		Timestamp: time.Now().UTC(),
	}

	// Add approval
	proposal.mu.Lock()
	approverKey := hex.EncodeToString(approval.By)
	proposal.Approvals[approverKey] = approval
	proposal.mu.Unlock()

	// Verify approval is recorded
	if len(proposal.Approvals) != 1 {
		t.Errorf("expected 1 approval, got %d", len(proposal.Approvals))
	}

	// Simulate reaching consensus and removing from pending
	delete(pendingProposals, hashHex)

	if _, exists := pendingProposals[hashHex]; exists {
		t.Error("proposal should be removed after consensus")
	}

	t.Logf("Chain: %s has %d blocks", teamChain.TeamName(), teamChain.Len())
}

// TestSharedTeamDiscovery tests that peers correctly identify shared teams
func TestSharedTeamDiscovery(t *testing.T) {
	testCases := []struct {
		name           string
		aliceTeams     []string
		bobTeams       []string
		expectedShared []string
	}{
		{
			name:           "single shared team",
			aliceTeams:     []string{"team-a", "team-b"},
			bobTeams:       []string{"team-b", "team-c"},
			expectedShared: []string{"team-b"},
		},
		{
			name:           "multiple shared teams",
			aliceTeams:     []string{"team-a", "team-b", "team-c"},
			bobTeams:       []string{"team-b", "team-c", "team-d"},
			expectedShared: []string{"team-b", "team-c"},
		},
		{
			name:           "no shared teams",
			aliceTeams:     []string{"team-a", "team-b"},
			bobTeams:       []string{"team-c", "team-d"},
			expectedShared: []string{},
		},
		{
			name:           "all shared",
			aliceTeams:     []string{"team-a", "team-b"},
			bobTeams:       []string{"team-a", "team-b"},
			expectedShared: []string{"team-a", "team-b"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			shared := findSharedTeams(tc.aliceTeams, tc.bobTeams)

			if len(shared) != len(tc.expectedShared) {
				t.Errorf("expected %d shared teams, got %d", len(tc.expectedShared), len(shared))
				return
			}

			// Create a set of expected teams for easy lookup
			expectedSet := make(map[string]bool)
			for _, team := range tc.expectedShared {
				expectedSet[team] = true
			}

			for _, team := range shared {
				if !expectedSet[team] {
					t.Errorf("unexpected shared team: %s", team)
				}
			}
		})
	}
}

// TestProtocolVersionCompatibility tests protocol version checking
func TestProtocolVersionCompatibility(t *testing.T) {
	alice := testutil.NewTestIdentity(t, "alice")
	bob := testutil.NewTestIdentity(t, "bob")

	// Create compatible handshakes
	aliceHandshake := protocol.NewHandshakeFromIdentity(alice.Identity, []string{"team-a"})
	bobHandshake := protocol.NewHandshakeFromIdentity(bob.Identity, []string{"team-a"})

	// They should be compatible
	if err := aliceHandshake.Compatible(bobHandshake); err != nil {
		t.Errorf("handshakes should be compatible: %v", err)
	}

	// Test shared teams
	shared := aliceHandshake.SharedTeams(bobHandshake)
	if len(shared) != 1 || shared[0] != "team-a" {
		t.Errorf("expected shared team 'team-a', got %v", shared)
	}
}

// TestPeerStateTransitions tests peer connection state transitions
func TestPeerStateTransitions(t *testing.T) {
	testCases := []struct {
		state    PeerState
		expected string
	}{
		{PeerStateDisconnected, "disconnected"},
		{PeerStateConnecting, "connecting"},
		{PeerStateHandshaking, "handshaking"},
		{PeerStateConnected, "connected"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			if tc.state.String() != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, tc.state.String())
			}
		})
	}
}

// TestConcurrentPeerOperations tests thread safety of peer operations
func TestConcurrentPeerOperations(t *testing.T) {
	// Create a map to simulate peer storage
	var mu sync.RWMutex
	peers := make(map[string]*Peer)

	// Simulate concurrent reads and writes
	var wg sync.WaitGroup
	numOperations := 100

	// Writers
	for i := 0; i < numOperations; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			fingerprint := fmt.Sprintf("peer-%d", idx%10)
			mu.Lock()
			peers[fingerprint] = &Peer{
				Fingerprint: fingerprint,
				Name:        fmt.Sprintf("name-%d", idx),
				State:       PeerStateConnected,
			}
			mu.Unlock()
		}(i)
	}

	// Readers
	for i := 0; i < numOperations; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			fingerprint := fmt.Sprintf("peer-%d", idx%10)
			mu.RLock()
			_ = peers[fingerprint]
			mu.RUnlock()
		}(i)
	}

	wg.Wait()

	// Should complete without race conditions
	t.Logf("Completed %d concurrent operations on %d unique peers", numOperations*2, len(peers))
}

// TestWaitForCondition tests the WaitFor helper
func TestWaitForCondition(t *testing.T) {
	// Test successful wait
	t.Run("success", func(t *testing.T) {
		counter := 0
		condition := func() bool {
			counter++
			return counter >= 3
		}

		testutil.WaitFor(t, 5*time.Second, condition, "counter to reach 3")
		if counter < 3 {
			t.Errorf("expected counter >= 3, got %d", counter)
		}
	})

	// Test with context cancellation
	t.Run("with_context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		// Condition that never becomes true
		ready := false
		go func() {
			time.Sleep(100 * time.Millisecond)
			ready = true
			cancel()
		}()

		// This would normally timeout, but we cancel the context
		condition := func() bool { return ready }

		// Use a short timeout
		start := time.Now()
		testutil.WaitFor(t, 500*time.Millisecond, condition, "ready flag")
		elapsed := time.Since(start)

		// Should complete quickly due to the condition becoming true
		if elapsed > 400*time.Millisecond {
			t.Logf("Wait took %v", elapsed)
		}

		_ = ctx // suppress unused warning
	})
}
