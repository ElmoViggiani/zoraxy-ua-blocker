// Package store implements thread-safe persistence of the User-Agent
// blocklist (entries + match counters) to a JSON file on disk.
package store

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
)

// Entry is one row in the blocklist: a User-Agent substring to match
// against, and a counter of how many times it has matched.
type Entry struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// Snapshot is both the on-disk file shape and the read-only view returned
// to the UI / API. Slices in a Snapshot returned from BlockList.Snapshot
// are caller-owned copies and safe to mutate.
type Snapshot struct {
	Entries      []Entry `json:"entries"`
	TotalBlocked int64   `json:"total_blocked"`
}

// BlockList holds the live in-memory state plus the path it's persisted
// to. `dirty` tracks whether RecordMatch increments need flushing — used
// by the background flusher to avoid disk writes when nothing has
// changed since the last tick.
type BlockList struct {
	mu           sync.RWMutex
	path         string
	entries      []Entry
	totalBlocked int64
	dirty        bool
}

// NewBlockList opens (or creates) the JSON file at `path` and returns a
// ready-to-use BlockList. If the file is missing, an empty one is
// created. If present, it must already be in the canonical
// {"entries":[…], "total_blocked":N} shape.
func NewBlockList(path string) (*BlockList, error) {
	bl := &BlockList{path: path, entries: []Entry{}}

	// Missing file: create empty and return.
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := bl.save(); err != nil {
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
	bl.totalBlocked = snap.TotalBlocked
	return bl, nil
}

// Snapshot returns a deep copy of current state for the API to serialise.
func (bl *BlockList) Snapshot() Snapshot {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	out := Snapshot{
		Entries:      make([]Entry, len(bl.entries)),
		TotalBlocked: bl.totalBlocked,
	}
	copy(out.Entries, bl.entries)
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
	bl.entries = append(bl.entries, Entry{Value: value, Count: 0})
	return bl.save()
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
			return bl.save()
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
	return bl.save()
}

// RecordMatch checks the User-Agent against the blocklist and, if any
// entry matches (case-insensitive substring), increments that entry's
// counter and the global total. Returns the matched entry value, or ""
// for no match. The increment is in-memory only; the background flusher
// persists it.
func (bl *BlockList) RecordMatch(userAgent string) string {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	uaLower := strings.ToLower(userAgent)
	for i := range bl.entries {
		if strings.Contains(uaLower, strings.ToLower(bl.entries[i].Value)) {
			bl.entries[i].Count++
			bl.totalBlocked++
			bl.dirty = true
			return bl.entries[i].Value
		}
	}
	return ""
}

// FlushIfDirty persists current state to disk if there are unsaved
// counter increments. Cheap no-op when nothing has changed.
func (bl *BlockList) FlushIfDirty() error {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	if !bl.dirty {
		return nil
	}
	if err := bl.save(); err != nil {
		return err
	}
	bl.dirty = false
	return nil
}

// save serialises current state to disk. Caller must hold the write lock.
func (bl *BlockList) save() error {
	out := Snapshot{Entries: bl.entries, TotalBlocked: bl.totalBlocked}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(bl.path, data, 0644)
}
