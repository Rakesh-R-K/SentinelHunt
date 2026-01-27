package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// FlowKey uniquely identifies a network flow (5-tuple)
type FlowKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
}

// FlowData stores aggregated flow statistics
type FlowData struct {
	// Identity
	Key FlowKey

	// Packet-level data
	PacketCount   int
	TotalBytes    int
	PacketSizes   []int
	Timestamps    []time.Time
	FirstSeen     time.Time
	LastSeen      time.Time

	// DNS-specific
	DNSQuery           string
	DNSQueryLength     int
	DNSSubdomainDepth  int
	DNSEntropy         float64

	// Feature flags
	HasDNS bool
}

// FlowFeatures represents the final feature set for export
type FlowFeatures struct {
	// Identity
	SrcIP    string  `json:"src_ip"`
	DstIP    string  `json:"dst_ip"`
	SrcPort  uint16  `json:"src_port"`
	DstPort  uint16  `json:"dst_port"`
	Protocol string  `json:"protocol"`

	// Timestamps
	FirstSeen string  `json:"first_seen"`
	LastSeen  string  `json:"last_seen"`

	// Basic features
	PacketCount    int     `json:"packet_count"`
	Duration       float64 `json:"duration"`
	TotalBytes     int     `json:"total_bytes"`
	AvgPacketSize  float64 `json:"avg_packet_size"`

	// Temporal features
	MinIAT  float64 `json:"min_iat"`
	MaxIAT  float64 `json:"max_iat"`
	MeanIAT float64 `json:"mean_iat"`
	StdIAT  float64 `json:"std_iat"`

	// Rate features
	BytesPerSecond   float64 `json:"bytes_per_second"`
	PacketsPerSecond float64 `json:"packets_per_second"`
	AvgBytesPerPacket float64 `json:"avg_bytes_per_packet"`

	// DNS features
	DNSQueryLength    int     `json:"dns_query_length"`
	DNSSubdomainDepth int     `json:"dns_subdomain_depth"`
	DNSEntropy        float64 `json:"dns_entropy"`
}

// FlowTracker manages all active flows
type FlowTracker struct {
	flows       map[FlowKey]*FlowData
	mutex       sync.RWMutex
	config      *Config
	exportCount uint64
}

// NewFlowTracker creates a new flow tracker
func NewFlowTracker(cfg *Config) *FlowTracker {
	return &FlowTracker{
		flows:  make(map[FlowKey]*FlowData),
		config: cfg,
	}
}

// UpdateFlow updates an existing flow or creates a new one
func (ft *FlowTracker) UpdateFlow(key FlowKey, timestamp time.Time, length int, dnsQuery string) {
	ft.mutex.Lock()
	defer ft.mutex.Unlock()

	flow, exists := ft.flows[key]
	if !exists {
		// Create new flow
		flow = &FlowData{
			Key:         key,
			FirstSeen:   timestamp,
			PacketSizes: make([]int, 0, 100),
			Timestamps:  make([]time.Time, 0, 100),
		}
		ft.flows[key] = flow
	}

	// Update flow data
	flow.PacketCount++
	flow.TotalBytes += length
	flow.PacketSizes = append(flow.PacketSizes, length)
	flow.Timestamps = append(flow.Timestamps, timestamp)
	flow.LastSeen = timestamp

	// Handle DNS data
	if dnsQuery != "" && !flow.HasDNS {
		flow.DNSQuery = dnsQuery
		flow.DNSQueryLength = len(dnsQuery)
		flow.DNSSubdomainDepth = countSubdomains(dnsQuery)
		flow.DNSEntropy = calculateEntropy(dnsQuery)
		flow.HasDNS = true
	}

	// Memory protection: export old flows if too many in memory
	if len(ft.flows) > ft.config.MaxFlowsInMemory {
		log.Printf("[WARN] Flow memory limit reached (%d), forcing export", len(ft.flows))
		go ft.ExportExpiredFlows()
	}
}

// ExportExpiredFlows exports flows that have timed out
func (ft *FlowTracker) ExportExpiredFlows() int {
	ft.mutex.Lock()
	defer ft.mutex.Unlock()

	now := time.Now()
	timeout := time.Duration(ft.config.FlowTimeoutSeconds) * time.Second
	expiredFlows := make([]FlowFeatures, 0)

	for key, flow := range ft.flows {
		if now.Sub(flow.LastSeen) > timeout {
			features := ft.extractFeatures(flow)
			expiredFlows = append(expiredFlows, features)
			delete(ft.flows, key)
		}
	}

	if len(expiredFlows) > 0 {
		ft.exportToFile(expiredFlows)
		ft.exportCount += uint64(len(expiredFlows))
		stats.ExportedFlows = ft.exportCount
	}

	return len(expiredFlows)
}

// ExportAll exports all remaining flows (called on shutdown)
func (ft *FlowTracker) ExportAll() int {
	ft.mutex.Lock()
	defer ft.mutex.Unlock()

	allFlows := make([]FlowFeatures, 0, len(ft.flows))

	for _, flow := range ft.flows {
		features := ft.extractFeatures(flow)
		allFlows = append(allFlows, features)
	}

	if len(allFlows) > 0 {
		ft.exportToFile(allFlows)
		ft.exportCount += uint64(len(allFlows))
		stats.ExportedFlows = ft.exportCount
	}

	ft.flows = make(map[FlowKey]*FlowData)
	return len(allFlows)
}

// extractFeatures converts FlowData to FlowFeatures
func (ft *FlowTracker) extractFeatures(flow *FlowData) FlowFeatures {
	features := FlowFeatures{
		SrcIP:    flow.Key.SrcIP,
		DstIP:    flow.Key.DstIP,
		SrcPort:  flow.Key.SrcPort,
		DstPort:  flow.Key.DstPort,
		Protocol: flow.Key.Protocol,
		FirstSeen: flow.FirstSeen.Format(time.RFC3339Nano),
		LastSeen:  flow.LastSeen.Format(time.RFC3339Nano),
		PacketCount: flow.PacketCount,
		TotalBytes:  flow.TotalBytes,
	}

	// Calculate duration
	duration := flow.LastSeen.Sub(flow.FirstSeen).Seconds()
	features.Duration = roundFloat(duration, 6)

	// Calculate average packet size
	if flow.PacketCount > 0 {
		features.AvgPacketSize = roundFloat(float64(flow.TotalBytes)/float64(flow.PacketCount), 2)
	}

	// Calculate temporal features (Inter-Arrival Time)
	if len(flow.Timestamps) > 1 {
		iats := make([]float64, 0, len(flow.Timestamps)-1)
		for i := 1; i < len(flow.Timestamps); i++ {
			iat := flow.Timestamps[i].Sub(flow.Timestamps[i-1]).Seconds()
			iats = append(iats, iat)
		}

		features.MinIAT = roundFloat(minFloat64(iats), 6)
		features.MaxIAT = roundFloat(maxFloat64(iats), 6)
		features.MeanIAT = roundFloat(meanFloat64(iats), 6)
		features.StdIAT = roundFloat(stdFloat64(iats), 6)
	}

	// Calculate rate features
	if duration > 0 {
		features.BytesPerSecond = roundFloat(float64(flow.TotalBytes)/duration, 2)
		features.PacketsPerSecond = roundFloat(float64(flow.PacketCount)/duration, 2)
	}

	if flow.PacketCount > 0 {
		features.AvgBytesPerPacket = roundFloat(float64(flow.TotalBytes)/float64(flow.PacketCount), 2)
	}

	// DNS features
	features.DNSQueryLength = flow.DNSQueryLength
	features.DNSSubdomainDepth = flow.DNSSubdomainDepth
	features.DNSEntropy = roundFloat(flow.DNSEntropy, 4)

	return features
}

// exportToFile writes flows to JSON file
func (ft *FlowTracker) exportToFile(flows []FlowFeatures) {
	if len(flows) == 0 {
		return
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(ft.config.OutputDirectory, 0755); err != nil {
		log.Printf("[ERROR] Failed to create output directory: %v", err)
		return
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	filename := filepath.Join(ft.config.OutputDirectory, fmt.Sprintf("flows_live_%s.json", timestamp))

	// Marshal to JSON
	data, err := json.MarshalIndent(flows, "", "  ")
	if err != nil {
		log.Printf("[ERROR] Failed to marshal flows: %v", err)
		return
	}

	// Write to file
	if err := os.WriteFile(filename, data, 0644); err != nil {
		log.Printf("[ERROR] Failed to write flows: %v", err)
		return
	}

	log.Printf("[EXPORT] %d flows → %s", len(flows), filename)
}

// GetActiveFlowCount returns the number of active flows
func (ft *FlowTracker) GetActiveFlowCount() int {
	ft.mutex.RLock()
	defer ft.mutex.RUnlock()
	return len(ft.flows)
}

// ============================================
// HELPER FUNCTIONS
// ============================================

// countSubdomains counts the number of dots in a domain name
func countSubdomains(domain string) int {
	count := 0
	for _, c := range domain {
		if c == '.' {
			count++
		}
	}
	return count
}

// calculateEntropy computes Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	entropy := 0.0
	length := float64(len(s))

	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// Statistical helper functions
func minFloat64(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	min := values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
	}
	return min
}

func maxFloat64(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	max := values[0]
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	return max
}

func meanFloat64(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func stdFloat64(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	mean := meanFloat64(values)
	variance := 0.0
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	return math.Sqrt(variance / float64(len(values)))
}

func roundFloat(val float64, precision int) float64 {
	ratio := math.Pow(10, float64(precision))
	return math.Round(val*ratio) / ratio
}

// Sort helper for stable exports
func sortFlows(flows []FlowFeatures) {
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].FirstSeen < flows[j].FirstSeen
	})
}
