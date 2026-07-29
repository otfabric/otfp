// SPDX-License-Identifier: MIT

// Package otfp provides convenience functions for OT protocol fingerprinting.
package otfp

import (
	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/protocols/bacnet"
	"github.com/otfabric/go-otfp/protocols/can"
	"github.com/otfabric/go-otfp/protocols/dnp3"
	"github.com/otfabric/go-otfp/protocols/enip"
	"github.com/otfabric/go-otfp/protocols/iec104"
	"github.com/otfabric/go-otfp/protocols/mms"
	"github.com/otfabric/go-otfp/protocols/modbus"
	"github.com/otfabric/go-otfp/protocols/opcua"
	"github.com/otfabric/go-otfp/protocols/profinet"
	"github.com/otfabric/go-otfp/protocols/s7"
)

// DefaultRegistry returns a Registry pre-loaded with all built-in protocol
// fingerprinters in their canonical priority order.
func DefaultRegistry() *core.Registry {
	registry := core.NewRegistry()
	_ = registry.Register(mms.New())
	_ = registry.Register(s7.New())
	_ = registry.Register(enip.New())
	_ = registry.Register(iec104.New())
	_ = registry.Register(dnp3.New())
	_ = registry.Register(modbus.New())
	_ = registry.Register(opcua.New())
	_ = registry.Register(bacnet.New())
	_ = registry.Register(can.New())
	_ = registry.Register(profinet.New())
	return registry
}
