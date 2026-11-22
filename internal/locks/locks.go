// Package locks provides per-key mutual exclusion.
//
// The auth service must serialize a handful of state transitions per account
// so that two concurrent requests cannot both observe "no account exists" and
// both try to create it, or both consume the same one-time ceremony. A mutex
// striped by account key does that without a global lock and without any
// database-level lock that could be held across network I/O.
package locks

import (
	"hash/fnv"
	"sync"
)

// Stripes is a fixed-size set of mutexes keyed by a byte key.
type Stripes struct {
	locks []sync.Mutex
}

// New returns a Striped lock set with the given number of stripes.
func New(n int) *Stripes {
	if n <= 0 {
		n = 256
	}
	return &Stripes{locks: make([]sync.Mutex, n)}
}

// Lock key and return the unlock function.
func (s *Stripes) Lock(key []byte) (unlock func()) {
	h := fnv.New32a()
	_, _ = h.Write(key)
	m := &s.locks[int(h.Sum32())%len(s.locks)]
	m.Lock()
	return m.Unlock
}
