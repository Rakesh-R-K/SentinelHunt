package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gopkg.in/yaml.v3"
)

// Config holds the application configuration
type Config struct {
	Interface            string `yaml:"interface"`
	SnapshotLength       int32  `yaml:"snapshot_length"`
	PromiscuousMode      bool   `yaml:"promiscuous_mode"`
	TimeoutMs            int    `yaml:"timeout_ms"`
	BpfFilter            string `yaml:"bpf_filter"`
	FlowTimeoutSeconds   int    `yaml:"flow_timeout_seconds"`
	MaxFlowsInMemory     int    `yaml:"max_flows_in_memory"`
	OutputDirectory      string `yaml:"output_directory"`
	OutputFormat         string `yaml:"output_format"`
	ExportIntervalSeconds int   `yaml:"export_interval_seconds"`
	EnableDnsFeatures    bool   `yaml:"enable_dns_features"`
	EnableTemporalFeatures bool `yaml:"enable_temporal_features"`
	EnableRateFeatures   bool   `yaml:"enable_rate_features"`
	LogLevel             string `yaml:"log_level"`
	LogFile              string `yaml:"log_file"`
}

// PacketStats holds runtime statistics
type PacketStats struct {
	TotalPackets   uint64
	TCPPackets     uint64
	UDPPackets     uint64
	DNSPackets     uint64
	ActiveFlows    int
	ExportedFlows  uint64
	DroppedPackets uint64
}

var (
	configFile = flag.String("config", "config.yaml", "Path to configuration file")
	pcapFile   = flag.String("pcap", "", "Read from PCAP file instead of live capture")
	stats      PacketStats
	config     Config
	tracker    *FlowTracker
)

func main() {
	flag.Parse()

	// Load configuration
	if err := loadConfig(*configFile); err != nil {
		log.Fatalf("[FATAL] Failed to load config: %v", err)
	}

	log.Printf("[INFO] SentinelHunt Collector v1.0.0")
	log.Printf("[INFO] Interface: %s", config.Interface)
	log.Printf("[INFO] BPF Filter: %s", config.BpfFilter)

	// Initialize flow tracker
	tracker = NewFlowTracker(&config)

	// Setup signal handler for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start packet capture
	var handle *pcap.Handle
	var err error

	if *pcapFile != "" {
		// Read from PCAP file
		log.Printf("[INFO] Reading from PCAP: %s", *pcapFile)
		handle, err = pcap.OpenOffline(*pcapFile)
	} else {
		// Live capture
		log.Printf("[INFO] Starting live capture...")
		handle, err = pcap.OpenLive(
			config.Interface,
			config.SnapshotLength,
			config.PromiscuousMode,
			time.Duration(config.TimeoutMs)*time.Millisecond,
		)
	}

	if err != nil {
		log.Fatalf("[FATAL] Failed to open capture: %v", err)
	}
	defer handle.Close()

	// Apply BPF filter
	if err := handle.SetBPFFilter(config.BpfFilter); err != nil {
		log.Fatalf("[FATAL] Failed to set BPF filter: %v", err)
	}

	// Start periodic export goroutine
	go periodicExport()

	// Start statistics display goroutine
	go displayStats()

	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	log.Printf("[INFO] Collector started. Press Ctrl+C to stop.")

	for {
		select {
		case packet := <-packetChan:
			if packet == nil {
				// End of PCAP file
				log.Printf("[INFO] End of capture reached")
				goto shutdown
			}
			processPacket(packet)
			stats.TotalPackets++

		case <-sigChan:
			log.Printf("[INFO] Shutdown signal received")
			goto shutdown
		}
	}

shutdown:
	log.Printf("[INFO] Exporting remaining flows...")
	tracker.ExportAll()
	displayFinalStats()
	log.Printf("[INFO] Collector stopped gracefully")
}

// loadConfig reads and parses the YAML configuration file
func loadConfig(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, &config)
}

// processPacket extracts flow information and updates tracker
func processPacket(packet gopacket.Packet) {
	// Extract network layer
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	// Extract transport layer
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return
	}

	var srcIP, dstIP string
	var srcPort, dstPort uint16
	var protocol string

	// Parse IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else {
		return
	}

	// Parse transport layer
	switch transportLayer.LayerType() {
	case layers.LayerTypeTCP:
		tcp, _ := transportLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		protocol = "TCP"
		stats.TCPPackets++

	case layers.LayerTypeUDP:
		udp, _ := transportLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		protocol = "UDP"
		stats.UDPPackets++

		// Check for DNS
		if dstPort == 53 || srcPort == 53 {
			stats.DNSPackets++
		}

	default:
		return
	}

	// Get packet metadata
	metadata := packet.Metadata()
	timestamp := metadata.Timestamp
	length := metadata.Length

	// Extract DNS query if present
	var dnsQuery string
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		if len(dns.Questions) > 0 {
			dnsQuery = string(dns.Questions[0].Name)
		}
	}

	// Update flow tracker
	flowKey := FlowKey{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}

	tracker.UpdateFlow(flowKey, timestamp, length, dnsQuery)
}

// periodicExport exports flows at regular intervals
func periodicExport() {
	ticker := time.NewTicker(time.Duration(config.ExportIntervalSeconds) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		exported := tracker.ExportExpiredFlows()
		if exported > 0 {
			log.Printf("[INFO] Periodic export: %d flows", exported)
		}
	}
}

// displayStats shows runtime statistics
func displayStats() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats.ActiveFlows = tracker.GetActiveFlowCount()
		log.Printf("[STATS] Packets: %d | TCP: %d | UDP: %d | DNS: %d | Active Flows: %d | Exported: %d",
			stats.TotalPackets, stats.TCPPackets, stats.UDPPackets,
			stats.DNSPackets, stats.ActiveFlows, stats.ExportedFlows)
	}
}

// displayFinalStats shows final statistics before shutdown
func displayFinalStats() {
	log.Printf("═══════════════════════════════════════════")
	log.Printf("  FINAL STATISTICS")
	log.Printf("═══════════════════════════════════════════")
	log.Printf("  Total Packets:    %d", stats.TotalPackets)
	log.Printf("  TCP Packets:      %d", stats.TCPPackets)
	log.Printf("  UDP Packets:      %d", stats.UDPPackets)
	log.Printf("  DNS Packets:      %d", stats.DNSPackets)
	log.Printf("  Exported Flows:   %d", stats.ExportedFlows)
	log.Printf("═══════════════════════════════════════════")
}

// Helper function to export stats as JSON
func ExportStatsJSON(filename string) error {
	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}
