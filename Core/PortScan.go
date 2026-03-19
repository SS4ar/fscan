package Core

import (
	"context"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// EnhancedPortScan performs high-performance port scanning with:
// - SocketIterator for port spraying (evasion) and priority sorting
// - AdaptivePool for dynamic concurrency tuning
// - connectWithRetry for handling resource exhaustion
func EnhancedPortScan(hosts []string, ports string, timeout int64) []string {
	// Parse ports and exclusions
	portList := Common.ParsePort(ports)
	if len(portList) == 0 {
		Common.LogError("Invalid port: " + ports)
		return nil
	}

	exclude := make(map[int]struct{})
	for _, p := range Common.ParsePort(Common.ExcludePorts) {
		exclude[p] = struct{}{}
	}

	// Create socket iterator (port spraying + priority sorting)
	iter := NewSocketIterator(hosts, portList, exclude)
	totalTasks := iter.Total()

	// Initialize adaptive concurrency pool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	to := time.Duration(timeout) * time.Second
	pool := NewAdaptivePool(Common.ThreadNum)
	var count int64
	var aliveMap sync.Map
	var wg sync.WaitGroup

	// Large-scale scan warning
	if totalTasks > 100000 {
		Common.LogInfo(fmt.Sprintf("Large-scale scan: %d targets (%d hosts × %d ports)",
			totalTasks, len(hosts), len(portList)))
	}

	// Port spraying: iterate through SocketIterator
	for {
		host, port, ok := iter.Next()
		if !ok {
			break
		}

		if err := pool.Acquire(ctx); err != nil {
			break
		}

		wg.Add(1)
		go func(host string, port int) {
			defer func() {
				pool.Release()
				wg.Done()
			}()

			pool.RecordPacket()
			addr := Common.FormatHostPort(host, port)

			// Connect with retry (handles resource exhaustion)
			conn, err := connectWithRetry(addr, to, 2, pool)
			if err != nil {
				return
			}
			defer conn.Close()

			// Record open port
			atomic.AddInt64(&count, 1)
			aliveMap.Store(addr, struct{}{})
			Common.LogInfo("Open port " + addr)
			Common.SaveResult(&Common.ScanResult{
				Time: time.Now(), Type: Common.PORT, Target: host,
				Status: "open", Details: map[string]interface{}{"port": port},
			})

			// Service identification
			if Common.EnableFingerprint {
				if info, err := NewPortInfoScanner(host, port, conn, to).Identify(); err == nil {
					// Build result details
					details := map[string]interface{}{"port": port, "service": info.Name}
					if info.Version != "" {
						details["version"] = info.Version
					}

					for k, v := range info.Extras {
						if v == "" {
							continue
						}
						switch k {
						case "vendor_product":
							details["product"] = v
						case "os", "info":
							details[k] = v
						}
					}
					if len(info.Banner) > 0 {
						details["banner"] = strings.TrimSpace(info.Banner)
					}

					Common.SaveResult(&Common.ScanResult{
						Time: time.Now(), Type: Common.SERVICE, Target: host,
						Status: "identified", Details: details,
					})

					// Log service info
					var sb strings.Builder
					sb.WriteString("Service identified " + addr + " => ")
					if info.Name != "unknown" {
						sb.WriteString("[" + info.Name + "]")
					}
					if info.Version != "" {
						sb.WriteString(" version:" + info.Version)
					}

					for k, v := range info.Extras {
						if v == "" {
							continue
						}
						switch k {
						case "vendor_product":
							sb.WriteString(" product:" + v)
						case "os":
							sb.WriteString(" os:" + v)
						case "info":
							sb.WriteString(" info:" + v)
						}
					}

					if len(info.Banner) > 0 && len(info.Banner) < 100 {
						sb.WriteString(" banner:[" + strings.TrimSpace(info.Banner) + "]")
					}

					Common.LogInfo(sb.String())
				}
			}
		}(host, port)
	}

	wg.Wait()

	// Collect results
	var aliveAddrs []string
	aliveMap.Range(func(key, _ interface{}) bool {
		aliveAddrs = append(aliveAddrs, key.(string))
		return true
	})

	Common.LogBase(fmt.Sprintf("Scan completed, found %d open ports", count))
	return aliveAddrs
}

// connectWithRetry wraps TCP connection with retry for resource exhaustion errors.
// Only retries on OS resource limits (too many open files, etc.), not on port-closed errors.
func connectWithRetry(addr string, timeout time.Duration, maxRetries int, pool *AdaptivePool) (net.Conn, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		conn, err := net.DialTimeout("tcp", addr, timeout)

		if err == nil {
			return conn, nil
		}

		lastErr = err

		// Debug: log every connection error
		if attempt == 0 {
			Common.LogDebug(fmt.Sprintf("Port closed %s: %v", addr, err))
		}

		// Only retry on resource exhaustion errors
		if !IsResourceExhaustedError(err) {
			return nil, err
		}

		// Record resource exhaustion
		pool.RecordExhausted()
		Common.LogDebug(fmt.Sprintf("Resource exhausted on %s (attempt %d/%d): %v", addr, attempt+1, maxRetries, err))

		// Exponential backoff: 50ms, 150ms
		if attempt < maxRetries-1 {
			waitTime := time.Duration(50*(attempt+1)) * time.Millisecond
			time.Sleep(waitTime)
		}
	}

	return nil, lastErr
}
