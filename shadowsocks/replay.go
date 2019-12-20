package shadowsocks

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
)

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

type empty struct{}

// IVCache allows us to check whether an initialization vector was among
// the last `capacity` IVs.  It requires approximately 16*capacity bytes
// of memory, with a pre-hashing step to avoid storing the entire IV and
// activate Go's space optimization for uint64-keyed maps.
type IVCache struct {
	sync.Mutex
	capacity int
	active   map[uint64]empty
	archive  map[uint64]empty
	hasher   Hasher
}

// NewIVCache returns a fresh IVCache, initialized with a random salt.
// The zero value is a cache with capacity 0, i.e. no cache.
func NewIVCache(capacity int) IVCache {
	return IVCache{
		capacity: capacity,
		active:   make(map[uint64]empty),
		archive:  make(map[uint64]empty),
		hasher:   MakeByteHasher(),
	}
}

// Add an IV to the cache.  Returns false if the IV is already present.
func (c *IVCache) Add(iv [length]byte) bool {
	if c.capacity == 0 {
		// Cache is disabled, so every IV is new.
		return true
	}
	hash := c.hasher.Hash(iv)
	c.Lock()
	defer c.Unlock()
	if _, ok := c.archive[hash]; ok {
		return false
	}
	if _, ok := c.active[hash]; ok {
		return false
	}
	c.active[hash] = empty{}
	if len(c.active) == c.capacity {
		// Discard the archive and move active to archive.
		c.archive = c.active
		c.active = make(map[uint64]empty)
	}
	return true
}
