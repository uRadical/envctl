package chain

import (
	"bytes"
	"fmt"
	"log/slog"
	"time"
)

// ConflictResolution represents the outcome of conflict resolution
type ConflictResolution struct {
	Winner     *Block   // The winning block
	Loser      *Block   // The losing block
	RolledBack []*Block // Blocks that were rolled back
	Applied    []*Block // Blocks that were applied
	Reason     string   // Why this block won
}

// ResolveConflict deterministically resolves a chain fork.
// Both peers running this algorithm will arrive at the same result.
//
// Rules (in order):
// 1. Block with earlier timestamp wins
// 2. If timestamps equal (within tolerance), lower block hash wins
// 3. If still tied, compare signer fingerprints (lower wins)
func ResolveConflict(ourBlock, theirBlock *Block) (*Block, string) {
	// Rule 1: Earlier timestamp wins
	// Use a tolerance of 1 second to handle clock skew
	const timestampTolerance = time.Second

	ourTime := ourBlock.Timestamp
	theirTime := theirBlock.Timestamp
	timeDiff := ourTime.Sub(theirTime)

	if timeDiff > timestampTolerance {
		// Their block is significantly earlier
		return theirBlock, "earlier_timestamp"
	}
	if timeDiff < -timestampTolerance {
		// Our block is significantly earlier
		return ourBlock, "earlier_timestamp"
	}

	// Rule 2: Timestamps within tolerance - compare hashes
	// Lower hash wins (deterministic, no advantage to either party)
	ourHash := ourBlock.Hash
	theirHash := theirBlock.Hash

	hashCmp := bytes.Compare(ourHash, theirHash)
	if hashCmp < 0 {
		return ourBlock, "lower_hash"
	}
	if hashCmp > 0 {
		return theirBlock, "lower_hash"
	}

	// Rule 3: Hashes equal (extremely unlikely) - compare signer
	ourSigner := fmt.Sprintf("%x", ourBlock.ProposedBy)
	theirSigner := fmt.Sprintf("%x", theirBlock.ProposedBy)

	if ourSigner < theirSigner {
		return ourBlock, "lower_signer"
	}
	return theirBlock, "lower_signer"
}

// ResolveFork resolves a fork between two chains at a given divergence point.
// Returns the blocks to roll back and the blocks to apply.
func ResolveFork(ourChain, theirChain *Chain, divergeIndex int) (*ConflictResolution, error) {
	if divergeIndex < 0 || divergeIndex >= ourChain.Len() || divergeIndex >= theirChain.Len() {
		return nil, fmt.Errorf("invalid divergence index: %d", divergeIndex)
	}

	ourBlock := ourChain.Block(uint64(divergeIndex))
	theirBlock := theirChain.Block(uint64(divergeIndex))

	if ourBlock == nil || theirBlock == nil {
		return nil, fmt.Errorf("missing block at index %d", divergeIndex)
	}

	winner, reason := ResolveConflict(ourBlock, theirBlock)

	resolution := &ConflictResolution{
		Reason: reason,
	}

	if bytes.Equal(winner.Hash, ourBlock.Hash) {
		// Our chain wins
		resolution.Winner = ourBlock
		resolution.Loser = theirBlock
		resolution.RolledBack = nil
		resolution.Applied = nil

		slog.Info("fork resolved in our favor",
			"index", divergeIndex,
			"reason", reason,
			"our_hash", fmt.Sprintf("%x", ourBlock.Hash[:min(4, len(ourBlock.Hash))]),
			"their_hash", fmt.Sprintf("%x", theirBlock.Hash[:min(4, len(theirBlock.Hash))]))
	} else {
		// Their chain wins - we need to rollback and apply their blocks
		resolution.Winner = theirBlock
		resolution.Loser = ourBlock

		// Collect blocks to roll back (from our chain, divergeIndex onwards)
		for i := ourChain.Len() - 1; i >= divergeIndex; i-- {
			resolution.RolledBack = append(resolution.RolledBack, ourChain.Block(uint64(i)))
		}

		// Collect blocks to apply (from their chain, divergeIndex onwards)
		for i := divergeIndex; i < theirChain.Len(); i++ {
			resolution.Applied = append(resolution.Applied, theirChain.Block(uint64(i)))
		}

		slog.Info("fork resolved in their favor",
			"index", divergeIndex,
			"reason", reason,
			"rollback_count", len(resolution.RolledBack),
			"apply_count", len(resolution.Applied),
			"our_hash", fmt.Sprintf("%x", ourBlock.Hash[:min(4, len(ourBlock.Hash))]),
			"their_hash", fmt.Sprintf("%x", theirBlock.Hash[:min(4, len(theirBlock.Hash))]))
	}

	return resolution, nil
}

// FindDivergencePoint finds where two chains diverge.
// Returns -1 if chains don't share a common ancestor (shouldn't happen for valid chains)
// or if chains are identical.
func FindDivergencePoint(ourChain, theirChain *Chain) int {
	// Start from genesis and find first difference
	minLen := ourChain.Len()
	if theirChain.Len() < minLen {
		minLen = theirChain.Len()
	}

	for i := 0; i < minLen; i++ {
		ourBlock := ourChain.Block(uint64(i))
		theirBlock := theirChain.Block(uint64(i))

		if !bytes.Equal(ourBlock.Hash, theirBlock.Hash) {
			return i
		}
	}

	// No divergence in common length - divergence is at the longer chain's extension
	if ourChain.Len() != theirChain.Len() {
		return minLen
	}

	// Chains are identical
	return -1
}

// Rollback removes the last n blocks from the chain.
// Returns the removed blocks for potential re-application.
func (c *Chain) Rollback(n int) ([]*Block, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if n <= 0 {
		return nil, nil
	}

	if n > len(c.blocks)-1 { // Can't rollback genesis
		return nil, fmt.Errorf("cannot rollback %d blocks, chain only has %d non-genesis blocks",
			n, len(c.blocks)-1)
	}

	// Extract blocks being removed
	startIndex := len(c.blocks) - n
	removed := make([]*Block, n)
	copy(removed, c.blocks[startIndex:])

	// Truncate chain
	c.blocks = c.blocks[:startIndex]

	// Rebuild state from remaining blocks
	if err := c.rebuildState(); err != nil {
		return removed, fmt.Errorf("rebuild state after rollback: %w", err)
	}

	slog.Debug("chain rolled back",
		"removed_blocks", n,
		"new_length", len(c.blocks),
		"new_head", fmt.Sprintf("%x", c.blocks[len(c.blocks)-1].Hash[:min(4, len(c.blocks[len(c.blocks)-1].Hash))]))

	return removed, nil
}

// RollbackTo rolls back to a specific block hash.
// Returns the removed blocks.
func (c *Chain) RollbackTo(targetHash []byte) ([]*Block, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Find the target block
	targetIndex := -1
	for i, block := range c.blocks {
		if bytes.Equal(block.Hash, targetHash) {
			targetIndex = i
			break
		}
	}

	if targetIndex == -1 {
		return nil, fmt.Errorf("target block not found in chain")
	}

	if targetIndex == len(c.blocks)-1 {
		// Already at target
		return nil, nil
	}

	// Extract blocks being removed
	removed := make([]*Block, len(c.blocks)-targetIndex-1)
	copy(removed, c.blocks[targetIndex+1:])

	// Truncate chain
	c.blocks = c.blocks[:targetIndex+1]

	// Rebuild state from remaining blocks
	if err := c.rebuildState(); err != nil {
		return removed, fmt.Errorf("rebuild state after rollback: %w", err)
	}

	return removed, nil
}

// rebuildState rebuilds the chain state (members, policy) from blocks
func (c *Chain) rebuildState() error {
	// Reset state
	c.members = make(map[string]*Member)
	c.policy = nil
	c.dissolved = false
	c.dissolvedAt = time.Time{}
	c.dissolvedBy = nil

	// Replay all blocks to rebuild state
	for _, block := range c.blocks {
		if err := c.applyBlock(block); err != nil {
			return fmt.Errorf("apply block %d: %w", block.Index, err)
		}
	}

	return nil
}

// ApplyRemoteBlocks applies blocks received from another chain after conflict resolution.
// This is used when their chain wins and we need to switch to it.
func (c *Chain) ApplyRemoteBlocks(blocks []*Block) error {
	for _, block := range blocks {
		// Validate block
		if !block.VerifyHash() {
			return fmt.Errorf("block %d: invalid hash", block.Index)
		}
		if !block.VerifySignature() {
			return fmt.Errorf("block %d: invalid signature", block.Index)
		}

		// Apply block
		if err := c.AppendBlock(block); err != nil {
			return fmt.Errorf("append block %d: %w", block.Index, err)
		}
	}

	return nil
}
