package chain

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
)

// SyncManager handles chain synchronization with peers
type SyncManager struct {
	chain *Chain
	mu    sync.RWMutex
}

// NewSyncManager creates a new sync manager for a chain
func NewSyncManager(chain *Chain) *SyncManager {
	return &SyncManager{
		chain: chain,
	}
}

// SyncMessage represents a sync protocol message
type SyncMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// Sync message types
const (
	SyncMsgGetHead   = "get_head"
	SyncMsgHead      = "head"
	SyncMsgGetBlocks = "get_blocks"
	SyncMsgBlocks    = "blocks"
	SyncMsgNewBlock  = "new_block"
	SyncMsgProposal  = "proposal"
)

// HeadInfo contains information about the chain head
type HeadInfo struct {
	Index uint64 `json:"index"`
	Hash  []byte `json:"hash"`
}

// GetBlocksRequest requests blocks from a specific index
type GetBlocksRequest struct {
	FromIndex uint64 `json:"from_index"`
	MaxBlocks int    `json:"max_blocks,omitempty"`
}

// BlocksResponse contains requested blocks
type BlocksResponse struct {
	Blocks []*Block `json:"blocks"`
}

// SyncWithPeer synchronizes the chain with a peer
func (s *SyncManager) SyncWithPeer(conn net.Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)

	// Request peer's head
	if err := encoder.Encode(SyncMessage{Type: SyncMsgGetHead}); err != nil {
		return fmt.Errorf("send get_head: %w", err)
	}

	// Receive head response
	var headMsg SyncMessage
	if err := decoder.Decode(&headMsg); err != nil {
		return fmt.Errorf("receive head: %w", err)
	}

	if headMsg.Type != SyncMsgHead {
		return fmt.Errorf("unexpected message type: %s", headMsg.Type)
	}

	var peerHead HeadInfo
	if err := json.Unmarshal(headMsg.Payload, &peerHead); err != nil {
		return fmt.Errorf("parse head: %w", err)
	}

	// Check if we need to sync
	ourHead := s.chain.Head()
	if ourHead != nil && ourHead.Index >= peerHead.Index {
		slog.Debug("Chain is up to date", "our_index", ourHead.Index, "peer_index", peerHead.Index)
		return nil
	}

	// Request missing blocks
	fromIndex := uint64(0)
	if ourHead != nil {
		fromIndex = ourHead.Index + 1
	}

	getBlocksReq := GetBlocksRequest{FromIndex: fromIndex}
	payload, _ := json.Marshal(getBlocksReq)

	if err := encoder.Encode(SyncMessage{Type: SyncMsgGetBlocks, Payload: payload}); err != nil {
		return fmt.Errorf("send get_blocks: %w", err)
	}

	// Receive blocks
	var blocksMsg SyncMessage
	if err := decoder.Decode(&blocksMsg); err != nil {
		return fmt.Errorf("receive blocks: %w", err)
	}

	if blocksMsg.Type != SyncMsgBlocks {
		return fmt.Errorf("unexpected message type: %s", blocksMsg.Type)
	}

	var blocksResp BlocksResponse
	if err := json.Unmarshal(blocksMsg.Payload, &blocksResp); err != nil {
		return fmt.Errorf("parse blocks: %w", err)
	}

	// Apply blocks
	for _, block := range blocksResp.Blocks {
		if err := s.chain.AppendBlock(block); err != nil {
			return fmt.Errorf("append block %d: %w", block.Index, err)
		}
		slog.Debug("Synced block", "index", block.Index)
	}

	slog.Info("Chain synced", "blocks_added", len(blocksResp.Blocks))

	return nil
}

// HandleGetBlocks handles a get_blocks request from a peer
func (s *SyncManager) HandleGetBlocks(from uint64) ([]*Block, error) {
	return s.chain.Blocks(from), nil
}

// HandleBlocks handles received blocks from a peer
func (s *SyncManager) HandleBlocks(blocks []*Block) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, block := range blocks {
		if err := s.chain.AppendBlock(block); err != nil {
			return fmt.Errorf("append block %d: %w", block.Index, err)
		}
	}

	return nil
}

// BroadcastBlock broadcasts a new block to peers
func (s *SyncManager) BroadcastBlock(block *Block) error {
	// This would be called by the peer manager to broadcast to all connected peers
	// The actual broadcast implementation is in the peer manager
	return nil
}

// BroadcastProposal broadcasts a new proposal to peers
func (s *SyncManager) BroadcastProposal(proposal *Block) error {
	// This would be called by the peer manager to broadcast to all connected peers
	// The actual broadcast implementation is in the peer manager
	return nil
}

// ServeSync handles incoming sync requests on a connection
func (s *SyncManager) ServeSync(conn net.Conn) error {
	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)

	for {
		var msg SyncMessage
		if err := decoder.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("decode message: %w", err)
		}

		switch msg.Type {
		case SyncMsgGetHead:
			head := s.chain.Head()
			headInfo := HeadInfo{}
			if head != nil {
				headInfo.Index = head.Index
				headInfo.Hash = head.Hash
			}
			payload, _ := json.Marshal(headInfo)
			if err := encoder.Encode(SyncMessage{Type: SyncMsgHead, Payload: payload}); err != nil {
				return fmt.Errorf("send head: %w", err)
			}

		case SyncMsgGetBlocks:
			var req GetBlocksRequest
			if err := json.Unmarshal(msg.Payload, &req); err != nil {
				return fmt.Errorf("parse get_blocks: %w", err)
			}

			blocks, err := s.HandleGetBlocks(req.FromIndex)
			if err != nil {
				return fmt.Errorf("handle get_blocks: %w", err)
			}

			resp := BlocksResponse{Blocks: blocks}
			payload, _ := json.Marshal(resp)
			if err := encoder.Encode(SyncMessage{Type: SyncMsgBlocks, Payload: payload}); err != nil {
				return fmt.Errorf("send blocks: %w", err)
			}

		case SyncMsgNewBlock:
			var block Block
			if err := json.Unmarshal(msg.Payload, &block); err != nil {
				return fmt.Errorf("parse new_block: %w", err)
			}
			if err := s.chain.AppendBlock(&block); err != nil {
				slog.Warn("Failed to append received block", "error", err)
			}

		case SyncMsgProposal:
			// Handle proposal - would be forwarded to consensus handler
			slog.Debug("Received proposal", "payload_size", len(msg.Payload))

		default:
			slog.Warn("Unknown sync message type", "type", msg.Type)
		}
	}
}

// GetChain returns the managed chain
func (s *SyncManager) GetChain() *Chain {
	return s.chain
}
