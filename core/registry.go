package core

import (
	"fmt"
	"sort"
	"sync"
)

// Registry holds registered protocol fingerprinters.
// It is safe for concurrent use.
type Registry struct {
	mu           sync.RWMutex
	fingerprints []Fingerprinter
	byName       map[Protocol]Fingerprinter
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		byName: make(map[Protocol]Fingerprinter),
	}
}

// Register adds a fingerprinter to the registry.
// Returns an error if a fingerprinter with the same name is already registered.
func (r *Registry) Register(fp Fingerprinter) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := fp.Name()
	if _, exists := r.byName[name]; exists {
		return fmt.Errorf("fingerprinter %q already registered", name.String())
	}

	r.fingerprints = append(r.fingerprints, fp)
	r.byName[name] = fp
	return nil
}

// Get returns the fingerprinter for the given protocol, or nil if not found.
func (r *Registry) Get(protocol Protocol) Fingerprinter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byName[protocol]
}

// All returns all registered fingerprinters sorted by priority (lowest first).
func (r *Registry) All() []Fingerprinter {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Fingerprinter, len(r.fingerprints))
	copy(result, r.fingerprints)

	sort.Slice(result, func(i, j int) bool {
		return result[i].Priority() < result[j].Priority()
	})
	return result
}

// Names returns the protocol identifiers of all registered fingerprinters.
func (r *Registry) Names() []Protocol {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]Protocol, len(r.fingerprints))
	for i, fp := range r.fingerprints {
		names[i] = fp.Name()
	}
	return names
}
