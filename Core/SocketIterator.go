package Core

import (
	"sort"
	"sync"
)

// highPriorityPorts maps high-value ports to priority (lower = higher priority).
// These ports produce the most actionable results for pentesters.
var highPriorityPorts = map[int]int{
	80:    1,  // HTTP
	443:   2,  // HTTPS
	22:    3,  // SSH
	3389:  4,  // RDP
	445:   5,  // SMB
	3306:  6,  // MySQL
	1433:  7,  // MSSQL
	6379:  8,  // Redis
	21:    9,  // FTP
	23:    10, // Telnet
	8080:  11, // HTTP-Alt
	8443:  12, // HTTPS-Alt
	5432:  13, // PostgreSQL
	27017: 14, // MongoDB
	1521:  15, // Oracle
	5900:  16, // VNC
	25:    17, // SMTP
	110:   18, // POP3
	143:   19, // IMAP
	53:    20, // DNS
}

// SocketIterator generates host:port combinations in a streaming fashion.
// Uses port spraying strategy: Port1×AllIPs -> Port2×AllIPs -> ...
// This distributes traffic across targets, reducing per-host detection risk.
type SocketIterator struct {
	hosts   []string
	ports   []int
	hostIdx int
	portIdx int
	total   int
	mu      sync.Mutex
}

// NewSocketIterator creates a streaming iterator with smart port sorting.
// High-value ports are scanned first for faster actionable results.
func NewSocketIterator(hosts []string, ports []int, exclude map[int]struct{}) *SocketIterator {
	validPorts := filterExcludedPorts(ports, exclude)
	sortedPorts := sortPortsByPriority(validPorts)
	return &SocketIterator{
		hosts: hosts,
		ports: sortedPorts,
		total: len(hosts) * len(sortedPorts),
	}
}

// sortPortsByPriority sorts ports with high-value ports first, then ascending.
func sortPortsByPriority(ports []int) []int {
	if len(ports) <= 1 {
		return ports
	}

	result := make([]int, len(ports))
	copy(result, ports)

	sort.Slice(result, func(i, j int) bool {
		pi, pj := result[i], result[j]
		priI, okI := highPriorityPorts[pi]
		priJ, okJ := highPriorityPorts[pj]

		if okI && okJ {
			return priI < priJ
		}
		if okI {
			return true
		}
		if okJ {
			return false
		}
		return pi < pj
	})

	return result
}

// Next returns the next host:port combination. ok=false means iteration is done.
// Port spraying order: iterate all IPs for the same port before moving to next port.
func (it *SocketIterator) Next() (string, int, bool) {
	it.mu.Lock()
	defer it.mu.Unlock()

	if len(it.hosts) == 0 || it.portIdx >= len(it.ports) {
		return "", 0, false
	}

	host := it.hosts[it.hostIdx]
	port := it.ports[it.portIdx]

	// Port spraying: iterate all IPs first, then switch port
	it.hostIdx++
	if it.hostIdx >= len(it.hosts) {
		it.hostIdx = 0
		it.portIdx++
	}

	return host, port, true
}

// Total returns the total number of tasks (for progress tracking).
func (it *SocketIterator) Total() int {
	return it.total
}

// filterExcludedPorts removes excluded ports from the list.
func filterExcludedPorts(ports []int, exclude map[int]struct{}) []int {
	if len(exclude) == 0 {
		return ports
	}
	result := make([]int, 0, len(ports))
	for _, p := range ports {
		if _, excluded := exclude[p]; !excluded {
			result = append(result, p)
		}
	}
	return result
}
