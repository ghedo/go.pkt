// Provides the basic interface for packet capturing and injection. This should
// not be used directly. Use one of the available subpackages instead.
package capture

import "github.com/ghedo/hype/filter"
import "github.com/ghedo/hype/packet"

type Handle interface {
	LinkType() packet.Type

	SetMTU(mtu int) error
	SetPromiscMode(promisc bool) error
	SetMonitorMode(monitor bool) error

	ApplyFilter(filter *filter.Filter) error

	Activate() error

	Capture() ([]byte, error)
	Inject(raw_pkt []byte) error

	Close()
}
