package shadowsocks

import (
	"crypto/md5"
	"math"
	"math/rand"
	"testing"
)

func MakeVecs(n int) [][32]byte {
	vecs := make([][32]byte, n)
	for i := 0; i < n; i++ {
		rand.Read(vecs[i][:])
	}
	return vecs
}

func TestByteHash(t *testing.T) {
	hasher := MakeByteHasher()
	vecs := MakeVecs(2)
	if hasher.Hash(vecs[0]) == hasher.Hash(vecs[1]) {
		t.Error("Hash collision.  This is extremely improbable.")
	}
}

func BenchmarkByteHash(b *testing.B) {
	vecs := MakeVecs(b.N)
	hasher := MakeByteHasher()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.Hash(vecs[i])
	}
}

// To serve as a reference point for BenchmarkByteHash
func BenchmarkMD5(b *testing.B) {
	vecs := MakeVecs(b.N)
	hasher := md5.New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.Sum(vecs[i][:])
	}
}

func TestSet64(t *testing.T) {
	s := NewSet64(5)
	val := rand.Uint64()

	if s.Full(0.5) {
		t.Error("Empty set can't be half-full")
	}

	if s.Contains(val) {
		t.Error("Empty set can't contain any value")
	}

	if !s.Add(val) {
		t.Error("Add to an empty set can't fail")
	}

	if !s.Contains(val) {
		t.Error("Value was just added")
	}

	if s.Full(0.5) {
		t.Error("Set has space for 32 values")
	}
}

func TestSet64_Zero(t *testing.T) {
	s := NewSet64(5)
	if !s.Contains(0) {
		t.Error("Set64 only has false positives, so 0 has to be included")
	}

	if s.Add(0) {
		t.Error("0 is already included, so it can't be added")
	}
}

func TestSet64_Full(t *testing.T) {
	s := NewSet64(5)
	var vals [32]uint64
	for i := range vals {
		vals[i] = rand.Uint64()
		if !s.Add(vals[i]) {
			t.Errorf("Failed to add value %d, %d", i, vals[i])
		}
	}

	for i, v := range vals {
		if !s.Contains(v) {
			t.Errorf("Failed to find value %d, %d", i, v)
		}
	}

	extra := rand.Uint64()
	if s.Add(extra) {
		t.Error("Set is full, so Add should have failed")
	}
	if s.Contains(extra) {
		t.Error("We never added this value")
	}
}

func TestSet64_CollideLow(t *testing.T) {
	s := NewSet64(5)
	var i uint64
	for i = 1; i <= 32; i++ {
		if s.Contains(i) {
			t.Errorf("We haven't added %d yet", i)
		}
		if !s.Add(i) {
			t.Errorf("Add(%d) failed", i)
		}
		if !s.Contains(i) {
			t.Errorf("Missing value %d", i)
		}
	}
}

func TestSet64_CollideHigh(t *testing.T) {
	s := NewSet64(5)
	var i uint64
	for i = 0; i < 32; i++ {
		v := math.MaxUint64 - i
		if s.Contains(v) {
			t.Errorf("We haven't added %d yet", v)
		}
		if !s.Add(v) {
			t.Errorf("Add(%d) failed", v)
		}
		if !s.Contains(v) {
			t.Errorf("Missing value %v", v)
		}
	}
}

func BenchmarkSet64_Contains_95(b *testing.B) {
	s := NewSet64(20)
	src := make([]uint64, 1<<20)
	for i := range src {
		src[i] = rand.Uint64()
	}
	// Construct a set that is 95% full
	k := 0
	for !s.Full(0.95) {
		s.Add(src[k])
		k++
	}
	// The set contains `k` values.

	b.ResetTimer()
	// Check every value in the set until we have done b.N checks.
	j := 0
	for i := 0; i < b.N; i++ {
		s.Contains(src[j])
		j++
		if j == k {
			j = 0
		}
	}
}

type empty struct{}

// Baseline for BenchmarkSet64_Contains_95
func BenchmarkMap_Contains(b *testing.B) {
	m := map[uint64]empty{}
	src := make([]uint64, 1<<20)
	for i := range src {
		src[i] = rand.Uint64()
		m[src[i]] = empty{}
	}

	b.ResetTimer()
	// Check every value in the set until we have done b.N checks.
	j := 0
	for i := 0; i < b.N; i++ {
		if _, ok := m[src[j]]; ok {
			j++
			if j == len(src) {
				j = 0
			}
		}
	}
}

func BenchmarkSet64_NotContains_95(b *testing.B) {
	// Capacity for 2^20 elements.
	s := NewSet64(20)
	// Construct a set that is 95% full
	for !s.Full(0.95) {
		s.Add(rand.Uint64())
	}

	// Create an array with new random values.
	src := make([]uint64, 1<<20)
	for i := range src {
		src[i] = rand.Uint64()
	}

	b.ResetTimer()
	// Check `src` repeatedly until we have done b.N checks.
	j := 0
	for i := 0; i < b.N; i++ {
		s.Contains(src[j])
		j++
		if j == len(src) {
			j = 0
		}
	}
}

// Baseline for BenchmarkSet64_NotContains_95
func BenchmarkMap_NotContains(b *testing.B) {
	// Capacity for 2^20 elements.
	m := map[uint64]empty{}
	for i := 0; i < 1<<20; i++ {
		m[rand.Uint64()] = empty{}
	}

	// Create an array with new random values.
	src := make([]uint64, 1<<20)
	for i := range src {
		src[i] = rand.Uint64()
	}

	b.ResetTimer()
	// Check `src` repeatedly until we have done b.N checks.
	j := 0
	for i := 0; i < b.N; i++ {
		if _, ok := m[src[j]]; !ok {
			j++
			if j == len(src) {
				j = 0
			}
		}
	}
}

// Add values to the set until it reaches 95% full
func BenchmarkSet64_Add_95(b *testing.B) {
	// Capacity for 2^20 elements.
	var scale uint8 = 20
	s := NewSet64(scale)

	cap := 1 << scale
	limit := int(math.Floor(float64(cap) * 0.95))

	// Create an array with new random values.
	src := make([]uint64, limit)
	for i := range src {
		src[i] = rand.Uint64()
	}

	b.ResetTimer()
	// Check `src` repeatedly until we have done b.N checks.
	j := 0
	for i := 0; i < b.N; i++ {
		if s.Add(src[j]) {
			j++
			if j == len(src) {
				b.StopTimer()
				j = 0
				s.Clear()
				b.StartTimer()
			}
		}
	}
}

// Baseline for BenchmarkSet64_Add_95
func BenchmarkMap_Add(b *testing.B) {
	var scale uint8 = 20
	cap := 1 << scale
	limit := int(math.Floor(float64(cap) * 0.95))

	// Create an array with new random values.
	src := make([]uint64, limit)
	for i := range src {
		src[i] = rand.Uint64()
	}

	m := map[uint64]empty{}

	b.ResetTimer()
	// Check `src` repeatedly until we have done b.N checks.
	j := 0
	for i := 0; i < b.N; i++ {
		if _, ok := m[src[j]]; !ok {
			m[src[j]] = empty{}
			j++
			if j == len(src) {
				b.StopTimer()
				j = 0
				m = map[uint64]empty{}
				b.StartTimer()
			}
		}
	}
}

func TestIVCache_Active(t *testing.T) {
	vecs := MakeVecs(2)
	cache := NewIVCache(5)
	if !cache.Add(vecs[0]) {
		t.Error("First addition to a clean cache should succeed")
	}
	if cache.Add(vecs[0]) {
		t.Error("Duplicate add should fail")
	}
	if !cache.Add(vecs[1]) {
		t.Error("Addition of a new vector should succeed")
	}
	if cache.Add(vecs[1]) {
		t.Error("Second duplicate add should fail")
	}
}

func TestIVCache_Archive(t *testing.T) {
	n := 256
	vecs0 := MakeVecs(n)
	vecs1 := MakeVecs(n)
	vecs2 := MakeVecs(n)
	vecs3 := MakeVecs(n)
	// IVCache is guaranteed to remember n <= k < n * 4 vectors.
	cache := NewIVCache(n)
	// Add enough vectors to spill into the archive.
	for i, vecs := range [][][32]byte{vecs0, vecs1, vecs2, vecs3} {
		for _, v := range vecs {
			if !cache.Add(v) {
				t.Errorf("Round %d: Addition of a new vector should succeed", i)
			}
		}

		// Check that they are all remembered, even if they don't fit in
		// the active set.
		for _, v := range vecs {
			if cache.Add(v) {
				t.Errorf("Round %d: Duplicate add should fail", i)
			}
		}
	}

	if !cache.Add(vecs0[0]) {
		t.Error("Expected the first vector to be forgotten")
	}
}

func BenchmarkIVCache_Fit(b *testing.B) {
	vecs := MakeVecs(1e6)
	// All vectors will fit in the active set.
	cache := NewIVCache(len(vecs) * 2)
	b.ResetTimer()
	j := 0
	for i := 0; i < b.N; i++ {
		if !cache.Add(vecs[j]) {
			b.Error("Collision!")
		}
		j++
		if j == len(vecs) {
			b.StopTimer()
			j = 0
			cache = NewIVCache(len(vecs))
			b.StartTimer()
		}
	}
}

func BenchmarkIVCache_Overflow(b *testing.B) {
	vecs := MakeVecs(1e6)
	// Every addition will archive the active set.
	cache := NewIVCache(1)
	b.ResetTimer()
	j := 0
	for i := 0; i < b.N; i++ {
		if !cache.Add(vecs[j]) {
			b.Error("Collision!")
		}
		j++
		if j == len(vecs) {
			j = 0
		}
	}
}

func BenchmarkIVCache_Parallel(b *testing.B) {
	vecs := MakeVecs(b.N)
	c := make(chan [32]byte, b.N)
	for _, v := range vecs {
		c <- v
	}
	close(c)
	// Exercise both expansion and archiving.
	cache := NewIVCache(256)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !cache.Add(<-c) {
				b.Error("Collision!")
			}
		}
	})
}
