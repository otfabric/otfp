// Package otfp provides convenience functions for OT protocol fingerprinting.
package otfp

import (
	"github.com/otfabric/otfp/core"
	"github.com/otfabric/otfp/protocols/bacnet"
	"github.com/otfabric/otfp/protocols/can"
	"github.com/otfabric/otfp/protocols/dnp3"
	"github.com/otfabric/otfp/protocols/enip"
	"github.com/otfabric/otfp/protocols/iec104"
	"github.com/otfabric/otfp/protocols/mms"
	"github.com/otfabric/otfp/protocols/modbus"
	"github.com/otfabric/otfp/protocols/opcua"
	"github.com/otfabric/otfp/protocols/profinet"
	"github.com/otfabric/otfp/protocols/s7"
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
