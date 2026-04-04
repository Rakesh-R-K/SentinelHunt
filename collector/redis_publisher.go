package main

/*
SentinelHunt — Redis Stream Publisher for Go Collector

Provides optional Redis Stream publishing for flows.
When Redis is available, flows are published to 'sentinelhunt:flows'
in addition to being written to JSON files (dual-write for reliability).

Usage:
  - Set `enable_redis: true` in config.yaml
  - Ensure Redis is running on the configured host:port
  - Flows are published as flat key-value maps to the stream
*/

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisPublisher handles publishing flows to Redis Streams
type RedisPublisher struct {
	client       *redis.Client
	streamName   string
	connected    bool
	publishCount uint64
	ctx          context.Context
}

// RedisConfig holds Redis connection settings
type RedisConfig struct {
	Host       string `yaml:"host"`
	Port       int    `yaml:"port"`
	Password   string `yaml:"password"`
	DB         int    `yaml:"db"`
	StreamName string `yaml:"stream_name"`
}

// NewRedisPublisher creates a new Redis publisher
func NewRedisPublisher(host string, port int, password string) *RedisPublisher {
	rp := &RedisPublisher{
		streamName: "sentinelhunt:flows",
		ctx:        context.Background(),
	}

	// Allow env overrides
	if envHost := os.Getenv("SENTINELHUNT_REDIS_HOST"); envHost != "" {
		host = envHost
	}
	if envPort := os.Getenv("SENTINELHUNT_REDIS_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			port = p
		}
	}

	rp.client = redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", host, port),
		Password:     password,
		DB:           0,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     5,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rp.client.Ping(ctx).Err(); err != nil {
		log.Printf("[REDIS] Connection failed: %v — file-only mode", err)
		rp.connected = false
		return rp
	}

	rp.connected = true
	log.Printf("[REDIS] Connected to %s:%d", host, port)

	// Create consumer group (ignore error if already exists)
	rp.client.XGroupCreateMkStream(rp.ctx, rp.streamName, "sentinelhunt-workers", "0")

	return rp
}

// PublishFlow publishes a single flow to the Redis stream
func (rp *RedisPublisher) PublishFlow(features FlowFeatures) error {
	if !rp.connected || rp.client == nil {
		return nil // Silently skip when not connected
	}

	// Convert flow to flat map for Redis XADD
	flowMap := map[string]interface{}{
		"src_ip":              features.SrcIP,
		"dst_ip":              features.DstIP,
		"src_port":            strconv.Itoa(int(features.SrcPort)),
		"dst_port":            strconv.Itoa(int(features.DstPort)),
		"protocol":            features.Protocol,
		"first_seen":          features.FirstSeen,
		"last_seen":           features.LastSeen,
		"packet_count":        strconv.Itoa(features.PacketCount),
		"duration":            fmt.Sprintf("%.6f", features.Duration),
		"total_bytes":         strconv.Itoa(features.TotalBytes),
		"avg_packet_size":     fmt.Sprintf("%.2f", features.AvgPacketSize),
		"min_iat":             fmt.Sprintf("%.6f", features.MinIAT),
		"max_iat":             fmt.Sprintf("%.6f", features.MaxIAT),
		"mean_iat":            fmt.Sprintf("%.6f", features.MeanIAT),
		"std_iat":             fmt.Sprintf("%.6f", features.StdIAT),
		"bytes_per_second":    fmt.Sprintf("%.2f", features.BytesPerSecond),
		"packets_per_second":  fmt.Sprintf("%.2f", features.PacketsPerSecond),
		"avg_bytes_per_packet": fmt.Sprintf("%.2f", features.AvgBytesPerPacket),
		"dns_query_length":    strconv.Itoa(features.DNSQueryLength),
		"dns_subdomain_depth": strconv.Itoa(features.DNSSubdomainDepth),
		"dns_entropy":         fmt.Sprintf("%.4f", features.DNSEntropy),
	}

	// Publish to stream with automatic ID and max length
	_, err := rp.client.XAdd(rp.ctx, &redis.XAddArgs{
		Stream: rp.streamName,
		MaxLen: 100000,
		Approx: true,
		Values: flowMap,
	}).Result()

	if err != nil {
		log.Printf("[REDIS] Publish failed: %v", err)
		return err
	}

	rp.publishCount++
	return nil
}

// PublishBatch publishes multiple flows to the stream
func (rp *RedisPublisher) PublishBatch(flows []FlowFeatures) int {
	if !rp.connected {
		return 0
	}

	published := 0
	for _, flow := range flows {
		if err := rp.PublishFlow(flow); err == nil {
			published++
		}
	}

	if published > 0 {
		log.Printf("[REDIS] Published %d/%d flows to stream", published, len(flows))
	}

	return published
}

// GetStreamInfo returns info about the Redis stream
func (rp *RedisPublisher) GetStreamInfo() string {
	if !rp.connected {
		return "disconnected"
	}

	info, err := rp.client.XInfoStream(rp.ctx, rp.streamName).Result()
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}

	return fmt.Sprintf("length=%d, groups=%d, first=%v, last=%v",
		info.Length, info.Groups, info.FirstEntry.ID, info.LastEntry.ID)
}

// IsConnected returns whether Redis is connected
func (rp *RedisPublisher) IsConnected() bool {
	if !rp.connected {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return rp.client.Ping(ctx).Err() == nil
}

// Close closes the Redis connection
func (rp *RedisPublisher) Close() {
	if rp.client != nil {
		rp.client.Close()
		log.Printf("[REDIS] Connection closed (published %d flows)", rp.publishCount)
	}
}

// PublishFlowJSON publishes a flow as a single JSON blob (alternative format)
func (rp *RedisPublisher) PublishFlowJSON(features FlowFeatures) error {
	if !rp.connected {
		return nil
	}

	data, err := json.Marshal(features)
	if err != nil {
		return err
	}

	_, err = rp.client.XAdd(rp.ctx, &redis.XAddArgs{
		Stream: rp.streamName,
		MaxLen: 100000,
		Approx: true,
		Values: map[string]interface{}{
			"flow_json": string(data),
		},
	}).Result()

	return err
}
