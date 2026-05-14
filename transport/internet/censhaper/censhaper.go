// Package censhaper integrates the bootstrap filter into
// Xray-core's transport layer. It wraps connections AFTER TLS so that each
// configured slot size targets the final encrypted TLS record size on the
// wire. Censhaper learns the negotiated TLS overhead after handshake and
// subtracts it before executing the derived schedule directly.
//
// Usage in Xray JSON config:
//
//	"streamSettings": {
//	  "censhaperSettings": {
//	    "mode": "bootstrap",
//	    "disableTiming": true,
//	    "generatedFlow": {
//	      "generatorPath": "/path/to/obfs",
//	      "trafficProfilePath": "/path/to/tp.bin",
//	      "modelPath": "/path/to/model_assumptions.json",
//	      "numFlows": 5,
//	      "flowLength": 10
//	    }
//	  }
//	}
//
// The role (client/server) is inferred from context: Dial → client, Accept → server.
package censhaper

import (
	"context"
	"fmt"
	"net"
	"sync"

	censhaper "censhaper"
)

// Config is the JSON-level configuration for censhaper in Xray stream
// settings. Only TLS-derived bootstrap mode is supported now:
//   - slot 0 starts with a fixed encrypted bootstrap marker and may carry
//     proxy payload after it
//   - slots 1..9 come from the generator-backed disable-timing path
//   - both peers derive the row-selection seed from negotiated outer TLS
//     exporter keying material
//
// [NEW] GeneratedFlowConfig carries the external generator inputs for the
// bootstrap+disableTiming path. Censhaper still derives the per-connection seed
// from outer TLS exporter material; these settings only tell it how to ask the
// generator for candidate no-timing flows.
type GeneratedFlowConfig struct {
	GeneratorPath      string `json:"generatorPath,omitempty"`
	TrafficProfilePath string `json:"trafficProfilePath,omitempty"`
	ModelPath          string `json:"modelPath,omitempty"`
	NumFlows           uint32 `json:"numFlows,omitempty"`
	FlowLength         uint32 `json:"flowLength,omitempty"`
}

type Config struct {
	Mode  string      `json:"mode"`
	Slots []censhaper.Slot `json:"slots,omitempty"`
	// [NEW] Seed is kept only so older sideband JSON can be rejected with a
	// clear error. Bootstrap no longer accepts user-supplied seeds because the
	// row selector now comes from negotiated outer TLS session secrets.
	Seed          *uint64 `json:"seed,omitempty"`
	DisableTiming bool    `json:"disableTiming,omitempty"`
	// [NEW] GeneratedFlow is the only maintained bootstrap source and is used
	// only for bootstrap+disableTiming profile synthesis.
	GeneratedFlow *GeneratedFlowConfig `json:"generatedFlow,omitempty"`
}

// Manager holds the bootstrap filter for both roles and creates per-connection
// wrappers via Wrap.
// Thread-safe.
type Manager struct {
	mu           sync.Mutex
	clientFilter *censhaper.Filter
	serverFilter *censhaper.Filter
}

// NewManager creates a Manager from config. Runtime config errors surface at
// startup, not per-connection.
func NewManager(ctx context.Context, cfg *Config) (*Manager, error) {
	// [NEW] Bootstrap is now the only supported public entry point.
	mode := cfg.Mode
	if mode == "" {
		mode = "bootstrap"
	}
	if mode != "bootstrap" {
		return nil, fmt.Errorf("censhaper: unsupported mode %q; only bootstrap is implemented", mode)
	}

	// [NEW] Reject legacy explicit bootstrap seeds even if an older sideband
	// payload bypasses the JSON validation layer. The runtime must not fall
	// back to a user-supplied seed now that bootstrap is TLS-derived.
	if cfg.Seed != nil {
		return nil, fmt.Errorf("censhaper: bootstrap mode no longer accepts \"seed\"; the row selector is derived from negotiated TLS session secrets")
	}

	// [NEW] Keep the censhaper-facing generator settings in one value so both client
	// and server filters run the same deterministic retry loop once they derive
	// the shared TLS seed for a connection.
	var generatedFlow *censhaper.GeneratedFlowConfig
	if cfg.GeneratedFlow != nil {
		generatedFlow = &censhaper.GeneratedFlowConfig{
			GeneratorPath:      cfg.GeneratedFlow.GeneratorPath,
			TrafficProfilePath: cfg.GeneratedFlow.TrafficProfilePath,
			ModelPath:          cfg.GeneratedFlow.ModelPath,
			NumFlows:           int(cfg.GeneratedFlow.NumFlows),
			FlowLength:         int(cfg.GeneratedFlow.FlowLength),
		}
	}

	clientCfg := censhaper.Config{
		Role:          "client",
		Mode:          mode,
		DisableTiming: cfg.DisableTiming,
		// Censhaper consumes GeneratedFlow only in bootstrap+disableTiming.
		GeneratedFlow: generatedFlow,
	}
	clientFilter, err := censhaper.NewFilter(ctx, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("censhaper: create client filter: %w", err)
	}

	serverCfg := censhaper.Config{
		Role:          "server",
		Mode:          mode,
		DisableTiming: cfg.DisableTiming,
		// [NEW] Mirror the same generator configuration on the server so both
		// sides make identical per-connection candidate and retry decisions.
		GeneratedFlow: generatedFlow,
	}
	serverFilter, err := censhaper.NewFilter(ctx, serverCfg)
	if err != nil {
		clientFilter.Close(ctx)
		return nil, fmt.Errorf("censhaper: create server filter: %w", err)
	}

	return &Manager{
		clientFilter: clientFilter,
		serverFilter: serverFilter,
	}, nil
}

// WrapClient wraps a post-TLS connection for the dialer (client) side.
// The returned net.Conn is what the proxy protocol reads and writes through.
func (m *Manager) WrapClient(ctx context.Context, conn net.Conn) (net.Conn, error) {
	return m.clientFilter.Wrap(ctx, conn)
}

// WrapServer wraps a post-TLS connection for the listener (server) side.
func (m *Manager) WrapServer(ctx context.Context, conn net.Conn) (net.Conn, error) {
	return m.serverFilter.Wrap(ctx, conn)
}

// Close releases the bootstrap filter resources for both filters.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	if err := m.clientFilter.Close(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := m.serverFilter.Close(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
