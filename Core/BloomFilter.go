package Core

import (
	"hash/fnv"
)

// BloomFilter is a probabilistic data structure for ICMP packet deduplication.
// False positive rate ~1%, false negative rate 0%.
type BloomFilter struct {
	bits []bool
	size uint32
	k    uint32 // number of hash functions
}

// NewBloomFilter creates a bloom filter.
// size: expected number of elements
// falsePositiveRate: desired false positive rate (typically 0.01 = 1%)
func NewBloomFilter(size int, falsePositiveRate float64) *BloomFilter {
	// Optimal bit array size: m = -n*ln(p) / (ln(2)^2)
	// Simplified: m ≈ n * 10 for p=0.01
	m := uint32(size * 10)
	if m < 1024 {
		m = 1024 // minimum 1KB
	}

	// Optimal hash function count: k = (m/n) * ln(2)
	// Simplified: k ≈ 7 for p=0.01
	k := uint32(7)

	return &BloomFilter{
		bits: make([]bool, m),
		size: m,
		k:    k,
	}
}

// Add adds an element to the filter.
func (bf *BloomFilter) Add(data string) {
	for i := uint32(0); i < bf.k; i++ {
		pos := bf.hash(data, i)
		bf.bits[pos] = true
	}
}

// Contains checks if an element might exist in the filter.
// Returns true: element possibly exists (may be false positive)
// Returns false: element definitely does not exist
func (bf *BloomFilter) Contains(data string) bool {
	for i := uint32(0); i < bf.k; i++ {
		pos := bf.hash(data, i)
		if !bf.bits[pos] {
			return false
		}
	}
	return true
}

// hash computes hash value with seed for multiple hash functions.
func (bf *BloomFilter) hash(data string, seed uint32) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(data))
	for i := uint32(0); i < seed; i++ {
		_, _ = h.Write([]byte{byte(i)})
	}
	return h.Sum32() % bf.size
}
