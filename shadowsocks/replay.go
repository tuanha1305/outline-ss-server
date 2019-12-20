package shadowsocks

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"sync"
)

// Fix the length of all inputs at 32 bytes
const length = 32

// Hasher represents a salted 64-bit hash of a fixed-length array.
type Hasher interface {
	Hash([length]byte) uint64
}

// A Hasher that implements a classic Tabulation Hash:
// https://en.wikipedia.org/wiki/Tabulation_hashing
type byteHasher [length][256]uint64

// MakeByteHasher returns a Hasher that implements a tabulation hash.
func MakeByteHasher() Hasher {
	var h byteHasher
	for i := 0; i < length; i++ {
		for j := 0; j < 256; j++ {
			var num [8]byte
			if _, err := rand.Read(num[:]); err != nil {
				panic("Failed to acquire entropy")
			}
			h[i][j] = binary.BigEndian.Uint64(num[:])
		}
	}
	return &h
}

func (h *byteHasher) Hash(vec [length]byte) uint64 {
	var hash uint64
	for i := 0; i < length; i++ {
		hash ^= h[i][vec[i]]
	}
	return hash
}

// Set64 is an add-only set of uint64s, implemented as a linear-probing
// ordered prefix table.  For good performance, values should be uniformly
// distributed.  Zero is not an allowed value.
type Set64 struct {
	scale uint8
	vals  []uint64 // len(vals) == 1<<scale
	count int      // Number of nonzero values.
	wrap  int      // vals[wrap:] + vals[:wrap] is in ascending order, ignoring zeros.
}

// NewSet64 returns an empty Set64 with space for `2^scale` values.
func NewSet64(scale uint8) *Set64 {
	return &Set64{
		scale: scale,
		vals:  make([]uint64, 1<<scale),
	}
}

func (s *Set64) start(val uint64) int {
	i := int(val >> (64 - s.scale))
	if i < s.wrap {
		i = s.wrap
	}
	return i
}

// Contains returns true if `val` is in the set.
func (s *Set64) Contains(val uint64) bool {
	if val == 0 {
		return true
	}
	i := s.start(val)
	for {
		v := s.vals[i]
		if v == 0 || v > val {
			return false
		} else if v == val {
			return true
		}
		i++
		if i == len(s.vals) {
			i = 0
		}
		if i == s.wrap {
			return false
		}
	}
}

// Add accepts a value, and returns true if the value was added.
// The set must not be full when Add is called.
func (s *Set64) Add(val uint64) bool {
	if val == 0 {
		return false
	}
	if s.count == len(s.vals) {
		// This is an error condition.  The caller should avoid this.
		return false
	}
	i := s.start(val)
	for {
		v := s.vals[i]
		if v == 0 {
			s.vals[i] = val
			s.count++
			return true // val was added to the set.
		} else if v == val {
			return false // val was already in the set.
		} else if v > val {
			s.vals[i] = val // Swap values to maintain ordering and continue.
			val = v
		}
		i++
		if i == len(s.vals) {
			i = 0
		}
		if i == s.wrap {
			// We have reached the wrap point, so val is the largest value in vals,
			// and s.vals[i] is the smallest value (or 0).
			val, s.vals[i] = s.vals[i], val
			s.wrap++
			if val == 0 {
				s.count++
				return true
			}
			i++
		}
	}
}

// Full returns true if the set has reached or exceeded the specified occupancy fraction.
func (s *Set64) Full(fraction float64) bool {
	return s.count >= int(math.Floor(fraction*float64(len(s.vals))))
}

// Clear resets the set to its initial, empty state.
func (s *Set64) Clear() {
	for i := range s.vals {
		s.vals[i] = 0
	}
	s.count = 0
	s.wrap = 0
}

// IVCache is a thread-safe cache for initialization vectors.
type IVCache interface {
	// Add an IV to the cache.  Returns false if the IV is already present.
	Add(iv [length]byte) bool
}

// An implementation of IVCache using Set64, with a false-positive
// probability of N/2^64, where N is the number of cache entries.
type set64Cache struct {
	IVCache
	mutex  sync.Mutex
	toggle bool
	s1     *Set64
	s2     *Set64
	hasher Hasher
}

// The maximum occupancy to allow in the active set.
// Higher values have better memory efficiency, but additions take
// time O(1/(1 - occupancy)).
const maxOccupancy = 0.95

// Returns the scale needed for a Set64 to hold `n` values in less
// than the `maxOccupancy`
func scale(n int) uint8 {
	return uint8(math.Ilogb(float64(n) / maxOccupancy * 2))
}

// NewIVCache returns a fresh IVCache, initialized with a random salt.
// The cache promises to remember at least the last `n` IVs.
func NewIVCache(n int) IVCache {
	scale := scale(n)
	return &set64Cache{
		s1:     NewSet64(scale),
		s2:     NewSet64(scale),
		hasher: MakeByteHasher(),
	}
}

func (c *set64Cache) Add(iv [length]byte) bool {
	if c == nil {
		// Cache is disabled, so every IV is new.
		return true
	}
	hash := c.hasher.Hash(iv)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var active, archive *Set64
	if c.toggle {
		active, archive = c.s1, c.s2
	} else {
		active, archive = c.s2, c.s1
	}
	if archive.Contains(hash) {
		return false
	}
	if !active.Add(hash) {
		return false
	}
	if active.Full(maxOccupancy) {
		archive.Clear()
		c.toggle = !c.toggle
	}
	return true
}
