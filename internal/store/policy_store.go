package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"snapgfw/internal/model"
)

// PolicyStore manages atomic JSON persistence and synchronized updates for Policy.
type PolicyStore struct {
	path     string
	mu       sync.RWMutex
	policy   model.Policy
	onChange []func(model.Policy) error
}

// NewPolicyStore loads policy.json or initializes an empty passthrough baseline policy.
func NewPolicyStore(path string) (*PolicyStore, error) {
	ps := &PolicyStore{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		def := model.DefaultPolicy()
		ps.policy = def
		if err := ps.saveLocked(def); err != nil {
			return nil, err
		}
		return ps, nil
	}
	var p model.Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	mergeMissingProtocols(&p)
	if err := p.Validate(); err != nil {
		return nil, err
	}
	ps.policy = p
	return ps, nil
}

// mergeMissingProtocols reconciles loaded/updated policies against the active catalog:
// removes retired protocol IDs (e.g. legacy heuristic trojan) and appends newly added ones disabled.
func mergeMissingProtocols(p *model.Policy) {
	catalog := model.BaseProtocolCatalog()
	valid := make(map[model.ProtocolID]bool, len(catalog))
	for _, cat := range catalog {
		valid[cat.ID] = true
	}
	kept := make([]model.ProtocolRule, 0, len(catalog))
	existing := make(map[model.ProtocolID]bool, len(p.Protocols))
	for _, pr := range p.Protocols {
		if valid[pr.ID] && !existing[pr.ID] {
			kept = append(kept, pr)
			existing[pr.ID] = true
		}
	}
	for _, cat := range catalog {
		if !existing[cat.ID] {
			cat.Enabled = false
			kept = append(kept, cat)
		}
	}
	p.Protocols = kept
}

// OnChange registers a synchronous hook invoked whenever policy changes.
func (s *PolicyStore) OnChange(fn func(model.Policy) error) {
	s.mu.Lock()
	s.onChange = append(s.onChange, fn)
	s.mu.Unlock()
}

// Get returns a deep copy of the active Policy.
func (s *PolicyStore) Get() model.Policy {
	s.mu.RLock()
	p := clonePolicy(s.policy)
	s.mu.RUnlock()
	return p
}

// Update validates, notifies hooks, and atomically persists a new Policy.
func (s *PolicyStore) Update(next model.Policy) error {
	mergeMissingProtocols(&next)
	if err := next.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.policy
	for _, fn := range s.onChange {
		if err := fn(clonePolicy(next)); err != nil {
			// Roll back prior hooks if an applier rejects the change.
			for _, rollbackFn := range s.onChange {
				_ = rollbackFn(clonePolicy(prev))
			}
			return err
		}
	}
	if err := s.saveLocked(next); err != nil {
		return err
	}
	s.policy = next
	return nil
}

// ApplyPreset imports a built-in recommended preset into the editable policy (preserving Notify and TrustedTenants).
func (s *PolicyStore) ApplyPreset(presetID string, preserveNotify bool) (model.Policy, error) {
	next, err := model.LookupPreset(presetID)
	if err != nil {
		return model.Policy{}, err
	}
	if preserveNotify {
		cur := s.Get()
		next.Notify = cur.Notify
		next.TrustedTenants = cur.TrustedTenants
	}
	if err := s.Update(next); err != nil {
		return model.Policy{}, err
	}
	return next, nil
}

func (s *PolicyStore) saveLocked(p model.Policy) error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func clonePolicy(p model.Policy) model.Policy {
	raw, _ := json.Marshal(p)
	var out model.Policy
	_ = json.Unmarshal(raw, &out)
	return out
}
