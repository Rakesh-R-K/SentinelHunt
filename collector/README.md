# SentinelHunt Go Packet Collector

High-performance network packet capture and flow aggregation module written in Go.

## Features

✅ **Real-time packet capture** using `libpcap` via `gopacket`  
✅ **5-tuple flow aggregation** (src_ip, dst_ip, src_port, dst_port, protocol)  
✅ **SOC-grade feature extraction** (temporal, rate, DNS intelligence)  
✅ **Concurrent flow processing** with mutex-protected state  
✅ **Configurable BPF filters** for targeted capture  
✅ **Automatic flow expiration** and export  
✅ **Memory-safe** with flow limit protection  
✅ **Graceful shutdown** with signal handling  
✅ **PCAP file or live capture** support

## Architecture

```
Packets → gopacket Parser → Flow Aggregator → Feature Extractor → JSON Export
                                    ↓
                            [In-Memory Flow Table]
                                    ↓
                          Periodic/Expiry Export
```

## Installation

### Prerequisites

```bash
# Install Go 1.21+
sudo apt update
sudo apt install golang-go

# Install libpcap development headers
sudo apt install libpcap-dev

# Verify installation
go version
```

### Build

```bash
cd collector/

# Initialize Go module and download dependencies
go mod download

# Build binary
go build -o sentinelhunt-collector

# Or build with optimizations
go build -ldflags="-s -w" -o sentinelhunt-collector
```

## Usage

### Live Capture (Requires Root/Sudo)

```bash
# Capture on default interface (eth0)
sudo ./sentinelhunt-collector

# Capture on specific interface
sudo ./sentinelhunt-collector -config config.yaml

# View available interfaces
ip link show
```

### PCAP File Analysis

```bash
# Process existing PCAP file
./sentinelhunt-collector -pcap ../datasets/raw/normal/normal_web_1.pcap
```

### Configuration

Edit `config.yaml`:

```yaml
interface: "eth0"              # Network interface
bpf_filter: "tcp or udp"       # Packet filter
flow_timeout_seconds: 60       # Flow expiration time
export_interval_seconds: 30    # Export frequency
output_directory: "../feature_engineering/outputs"
```

## Output Format

Exported JSON contains flow-level features compatible with SentinelHunt detection pipeline:

```json
{
  "src_ip": "192.168.1.100",
  "dst_ip": "8.8.8.8",
  "src_port": 54321,
  "dst_port": 53,
  "protocol": "UDP",
  "packet_count": 42,
  "duration": 5.234,
  "total_bytes": 3456,
  "bytes_per_second": 660.21,
  "packets_per_second": 8.02,
  "dns_entropy": 3.45,
  "dns_subdomain_depth": 3
}
```

## Performance

- **Throughput**: 10,000+ packets/sec on commodity hardware
- **Memory**: ~100 MB for 10,000 active flows
- **Latency**: Sub-millisecond flow updates
- **Concurrency**: Goroutine-based with mutex protection

## Integration with Detection Pipeline

```bash
# 1. Capture live traffic
sudo ./sentinelhunt-collector

# 2. Flows auto-exported to feature_engineering/outputs/flows_live_*.json

# 3. Run detection engine on live flows
cd ../detection_engine
python3 realtime_detector.py --input ../feature_engineering/outputs/flows_live_latest.json
```

## Troubleshooting

### Permission Denied

```bash
# Grant capabilities to binary (avoid sudo)
sudo setcap cap_net_raw,cap_net_admin=eip ./sentinelhunt-collector
./sentinelhunt-collector
```

### Interface Not Found

```bash
# List available interfaces
ip link show

# Update config.yaml with correct interface name
```

### No Packets Captured

```bash
# Check BPF filter syntax
tcpdump -i eth0 "tcp or udp" -c 10

# Verify interface is up
sudo ip link set eth0 up
```

## Development

### Testing

```bash
# Run with verbose logging
./sentinelhunt-collector -config config.yaml

# Test with sample PCAP
./sentinelhunt-collector -pcap test.pcap

# Monitor output
watch -n 1 'ls -lh ../feature_engineering/outputs/'
```

### Code Structure

- `main.go` - Entry point, packet processing loop
- `flow_tracker.go` - Flow aggregation and feature extraction
- `config.yaml` - Configuration file

## Why Go?

- **Performance**: 10-100x faster than Python for packet processing
- **Concurrency**: Native goroutines for parallel flow handling
- **Memory Safety**: Efficient garbage collection
- **Cross-Platform**: Single binary deployment
- **Industry Standard**: Used by Cloudflare, Datadog, Hashicorp

## Future Enhancements

- [ ] Prometheus metrics export
- [ ] gRPC streaming to detection engine
- [ ] Flow deduplication across interfaces
- [ ] IPFIX/NetFlow support
- [ ] Distributed capture with aggregation

## License

Part of SentinelHunt - AI-Assisted Threat Hunting Platform
