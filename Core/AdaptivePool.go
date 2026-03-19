package Core

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shadow1ng/fscan/Common"
	"golang.org/x/sync/semaphore"
)

// resourceExhaustedPatterns are error patterns indicating OS resource limits.
var resourceExhaustedPatterns = []string{
	"too many open files",
	"no buffer space available",
	"cannot assign requested address",
	"connection reset by peer",
}

// AdaptivePool wraps semaphore.Weighted with automatic concurrency tuning.
// It monitors resource exhaustion errors and dynamically adjusts the pool size.
type AdaptivePool struct {
	sem         *semaphore.Weighted
	currentSize int64
	initialSize int64
	minSize     int64
	maxSize     int64

	// Monitoring
	exhaustedCount int64 // atomic
	packetCount    int64 // atomic
	checkInterval  time.Duration
	lastCheck      time.Time

	// Thresholds
	exhaustedThreshold float64 // rate to trigger downgrade (10%)
	recoveryThreshold  float64 // rate to allow upgrade (2%)

	mu sync.Mutex
}

// NewAdaptivePool creates an adaptive concurrency pool.
func NewAdaptivePool(size int) *AdaptivePool {
	minSize := int64(size / 4)
	if minSize < 10 {
		minSize = 10
	}

	return &AdaptivePool{
		sem:                semaphore.NewWeighted(int64(size)),
		currentSize:        int64(size),
		initialSize:        int64(size),
		minSize:            minSize,
		maxSize:            int64(size),
		checkInterval:      time.Second,
		lastCheck:          time.Now(),
		exhaustedThreshold: 0.10, // 10% error rate triggers downgrade
		recoveryThreshold:  0.02, // 2% allows recovery
	}
}

// Acquire acquires a slot, checking if pool needs resizing.
func (ap *AdaptivePool) Acquire(ctx context.Context) error {
	ap.maybeAdjust()
	return ap.sem.Acquire(ctx, 1)
}

// Release releases a slot.
func (ap *AdaptivePool) Release() {
	ap.sem.Release(1)
}

// RecordPacket increments the packet counter.
func (ap *AdaptivePool) RecordPacket() {
	atomic.AddInt64(&ap.packetCount, 1)
}

// RecordExhausted increments the resource exhaustion counter.
func (ap *AdaptivePool) RecordExhausted() {
	atomic.AddInt64(&ap.exhaustedCount, 1)
}

// CurrentSize returns the current pool capacity.
func (ap *AdaptivePool) CurrentSize() int64 {
	return atomic.LoadInt64(&ap.currentSize)
}

// maybeAdjust checks and potentially adjusts the pool size.
func (ap *AdaptivePool) maybeAdjust() {
	now := time.Now()

	ap.mu.Lock()
	if now.Sub(ap.lastCheck) < ap.checkInterval {
		ap.mu.Unlock()
		return
	}
	ap.lastCheck = now
	ap.mu.Unlock()

	currentExhausted := atomic.LoadInt64(&ap.exhaustedCount)
	currentPackets := atomic.LoadInt64(&ap.packetCount)

	// Need enough samples to judge
	if currentPackets < 100 {
		return
	}

	rate := float64(currentExhausted) / float64(currentPackets)
	currentSize := atomic.LoadInt64(&ap.currentSize)

	if rate > ap.exhaustedThreshold && currentSize > ap.minSize {
		// Downgrade: reduce by 20%
		newSize := int64(float64(currentSize) * 0.8)
		if newSize < ap.minSize {
			newSize = ap.minSize
		}
		atomic.StoreInt64(&ap.currentSize, newSize)
		Common.LogInfo(fmt.Sprintf("[AdaptivePool] Resource exhaustion rate %.1f%%, threads %d -> %d",
			rate*100, currentSize, newSize))
	} else if rate < ap.recoveryThreshold && currentSize < ap.maxSize {
		// Recovery: increase by 10% (conservative)
		newSize := int64(float64(currentSize) * 1.1)
		if newSize > ap.maxSize {
			newSize = ap.maxSize
		}
		if newSize > currentSize {
			atomic.StoreInt64(&ap.currentSize, newSize)
		}
	}

	// Reset counters for next interval
	atomic.StoreInt64(&ap.exhaustedCount, 0)
	atomic.StoreInt64(&ap.packetCount, 0)
}

// IsResourceExhaustedError checks if an error indicates OS resource limits.
func IsResourceExhaustedError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	for _, pattern := range resourceExhaustedPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}
	return false
}
