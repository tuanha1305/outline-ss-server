package shadowsocks

import (
	"crypto/md5"
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

func TestIVCache_Active(t *testing.T) {
	vecs := MakeVecs(2)
	cache := NewIVCache(10)
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
	vecs0 := MakeVecs(10)
	vecs1 := MakeVecs(10)
	cache := NewIVCache(10)
	// Add vectors to the active set until it hits the limit
	// and spills into the archive.
	for _, v := range vecs0 {
		if !cache.Add(v) {
			t.Error("Addition of a new vector should succeed")
		}
	}

	for _, v := range vecs0 {
		if cache.Add(v) {
			t.Error("Duplicate add should fail")
		}
	}

	// Repopulate the active set.
	for _, v := range vecs1 {
		if !cache.Add(v) {
			t.Error("Addition of a new vector should succeed")
		}
	}

	// Both active and archive are full.  Adding another vector
	// should wipe the archive.
	lastStraw := MakeVecs(1)[0]
	if !cache.Add(lastStraw) {
		t.Error("Addition of a new vector should succeed")
	}
	for _, v := range vecs0 {
		if !cache.Add(v) {
			t.Error("First 10 vectors should have been forgotten")
		}
	}
}

func BenchmarkIVCache_Fit(b *testing.B) {
	vecs := MakeVecs(b.N)
	// All vectors will fit in the active set.
	cache := NewIVCache(b.N + 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Add(vecs[i])
	}
}

func BenchmarkIVCache_Overflow(b *testing.B) {
	vecs := MakeVecs(b.N)
	// Every addition will archive the active set.
	cache := NewIVCache(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Add(vecs[i])
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
	cache := NewIVCache(100)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.Add(<-c)
		}
	})
}
