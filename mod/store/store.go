// Package store implements thread-safe persistence of the User-Agent
// blocklist (entries + match counters) to a JSON file on disk.
package store

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// Entry is one row in the blocklist: a User-Agent substring to match
// against, and a counter of how many times it has matched. `lower` is
// the lowercased Value, cached so RecordMatch can skip allocating a
// fresh lowercased copy of every entry on every request.
//
// Count is incremented by RecordMatch under the BlockList's RLock, so
// it must be accessed via sync/atomic whenever other goroutines might
// be concurrently incrementing. Methods holding the write Lock have
// exclusive access and may read/write Count directly.
type Entry struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
	lower string
}

// Snapshot is both the on-disk file shape and the read-only view returned
// to the UI / API. Slices in a Snapshot returned from BlockList.Snapshot
// are caller-owned copies and safe to mutate.
type Snapshot struct {
	Entries      []Entry `json:"entries"`
	TotalBlocked int64   `json:"total_blocked"`
}

// BlockList holds the live in-memory state plus the path it's persisted
// to.
//
// Concurrency model:
//   - Add/Remove/ResetCounts hold the write Lock and have exclusive
//     access; they may read/write counters directly.
//   - RecordMatch holds RLock so many requests can match concurrently;
//     it uses sync/atomic on Entry.Count and totalBlocked.
//   - Snapshot and FlushIfDirty hold RLock and build a deep copy with
//     atomic loads, then release the lock before any expensive work
//     (JSON marshal, disk write).
//
// `dirty` signals that there are unsaved counter increments. It is
// written from both RLock and Lock paths, so it is atomic.Bool.
type BlockList struct {
	mu           sync.RWMutex
	path         string
	entries      []Entry
	totalBlocked int64 // see Entry.Count comment
	dirty        atomic.Bool
}

// NewBlockList opens (or creates) the JSON file at `path` and returns a
// ready-to-use BlockList. If the file is missing, an empty one is
// created. If present, it must already be in the canonical
// {"entries":[…], "total_blocked":N} shape.
func NewBlockList(path string) (*BlockList, error) {
	bl := &BlockList{path: path, entries: []Entry{}}

	// Missing file: create empty and return.
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := bl.saveLocked(); err != nil {
			return nil, err
		}
		return bl, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return bl, nil
	}

	// Decode the canonical format. A nil Entries slice (e.g. from "{}")
	// is normalised to an empty slice so callers never see nil.
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	bl.entries = snap.Entries
	if bl.entries == nil {
		bl.entries = []Entry{}
	}
	for i := range bl.entries {
		bl.entries[i].lower = strings.ToLower(bl.entries[i].Value)
	}
	bl.totalBlocked = snap.TotalBlocked
	return bl, nil
}

// Snapshot returns a deep copy of current state for the API to serialise.
func (bl *BlockList) Snapshot() Snapshot {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	out := Snapshot{
		Entries:      make([]Entry, len(bl.entries)),
		TotalBlocked: atomic.LoadInt64(&bl.totalBlocked),
	}
	for i := range bl.entries {
		out.Entries[i] = Entry{
			Value: bl.entries[i].Value,
			Count: atomic.LoadInt64(&bl.entries[i].Count),
		}
	}
	return out
}

// Add inserts a new substring. Duplicates (case-insensitive) are
// ignored. New entries start with count 0. Persisted immediately because
// list edits are user-initiated and rare.
func (bl *BlockList) Add(value string) error {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	for _, e := range bl.entries {
		if strings.EqualFold(e.Value, value) {
			return nil
		}
	}
	bl.entries = append(bl.entries, Entry{Value: value, lower: strings.ToLower(value)})
	if err := bl.saveLocked(); err != nil {
		return err
	}
	bl.dirty.Store(false)
	return nil
}

// Remove deletes the first entry matching value (case-insensitive). The
// deleted entry's count is subtracted from the global total so the
// displayed total stays equal to the sum of visible per-entry counts.
func (bl *BlockList) Remove(value string) error {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	for i, e := range bl.entries {
		if strings.EqualFold(e.Value, value) {
			bl.totalBlocked -= e.Count
			if bl.totalBlocked < 0 {
				bl.totalBlocked = 0
			}
			bl.entries = append(bl.entries[:i], bl.entries[i+1:]...)
			if err := bl.saveLocked(); err != nil {
				return err
			}
			bl.dirty.Store(false)
			return nil
		}
	}
	return nil
}

// ResetCounts zeros all per-entry counts and the global total.
func (bl *BlockList) ResetCounts() error {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	for i := range bl.entries {
		bl.entries[i].Count = 0
	}
	bl.totalBlocked = 0
	if err := bl.saveLocked(); err != nil {
		return err
	}
	bl.dirty.Store(false)
	return nil
}

// RecordMatch checks the User-Agent against the blocklist and, if any
// entry matches (case-insensitive substring), increments that entry's
// counter and the global total. Returns the matched entry value, or ""
// for no match. The increment is in-memory only; the background flusher
// persists it.
//
// Runs under RLock so many requests can match concurrently. Increments
// go through sync/atomic to stay race-free with other matchers.
func (bl *BlockList) RecordMatch(userAgent string) string {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	uaLower := strings.ToLower(userAgent)
	for i := range bl.entries {
		if strings.Contains(uaLower, bl.entries[i].lower) {
			atomic.AddInt64(&bl.entries[i].Count, 1)
			atomic.AddInt64(&bl.totalBlocked, 1)
			bl.dirty.Store(true)
			return bl.entries[i].Value
		}
	}
	return ""
}

// FlushIfDirty persists current state to disk if there are unsaved
// counter increments. Cheap no-op when nothing has changed.
//
// Snapshots state under RLock then releases the lock before doing the
// JSON marshal and disk write, so disk latency never stalls the request
// hot path. On write failure the dirty flag is re-set so the next tick
// retries.
func (bl *BlockList) FlushIfDirty() error {
	if !bl.dirty.Load() {
		return nil
	}
	bl.mu.RLock()
	snap := Snapshot{
		Entries:      make([]Entry, len(bl.entries)),
		TotalBlocked: atomic.LoadInt64(&bl.totalBlocked),
	}
	for i := range bl.entries {
		snap.Entries[i] = Entry{
			Value: bl.entries[i].Value,
			Count: atomic.LoadInt64(&bl.entries[i].Count),
		}
	}
	bl.mu.RUnlock()

	// Clear dirty before the disk write. If a concurrent RecordMatch
	// sets it back to true while writeSnapshot is running, that
	// increment is captured next tick — at worst we re-marshal some
	// unchanged counters, which is idempotent.
	bl.dirty.Store(false)
	if err := writeSnapshot(bl.path, snap); err != nil {
		bl.dirty.Store(true)
		return err
	}
	return nil
}

// saveLocked serialises current state to disk. Caller must hold the
// write Lock so the slice and counters cannot change during marshal.
func (bl *BlockList) saveLocked() error {
	out := Snapshot{Entries: bl.entries, TotalBlocked: bl.totalBlocked}
	return writeSnapshot(bl.path, out)
}

// writeSnapshot marshals snap and writes it to path. No locks are
// taken — the caller owns snap and must not mutate it concurrently.
func writeSnapshot(path string, snap Snapshot) error {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
