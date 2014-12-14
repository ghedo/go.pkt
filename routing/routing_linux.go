package routing

import "fmt"
import "net"
import "syscall"
import "unsafe"

type rtmsg struct {
	family  uint8
	dst_len uint8
	src_len uint8
	tos     uint8
	table   uint8
	proto   uint8
	scope   uint8
	rtype   uint8
	flags   uint32
}

// List all available routes on the system.
func Routes() ([]*Route, error) {
	var routes []*Route

	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("Could not retrieve RIB: %s", err)
	}

	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, fmt.Errorf("Could not parse messages: %s")
	}

	for _, m := range msgs {
		if m.Header.Type == syscall.NLMSG_DONE {
			break
		}

		if m.Header.Type != syscall.RTM_NEWROUTE {
			continue
		}

		route := &Route{ Default: true }

		rtmsg := (*rtmsg)(unsafe.Pointer(&m.Data[0]))

		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			return nil, fmt.Errorf("Could not parse attr: %s", err)
		}

		for _, a := range attrs {
			switch a.Attr.Type {
			case syscall.RTA_SRC:
				route.SrcNet = &net.IPNet{
					IP:   net.IP(a.Value),
					Mask: net.CIDRMask(
						int(rtmsg.src_len),
						len(a.Value) * 8,
					),
				}

			case syscall.RTA_DST:
				route.DstNet = &net.IPNet{
					IP:   net.IP(a.Value),
					Mask: net.CIDRMask(
						int(rtmsg.dst_len),
						len(a.Value) * 8,
					),
				}

				route.Default = false

			case syscall.RTA_PREFSRC:
				route.PrefSrc = net.IP(a.Value)

			case syscall.RTA_GATEWAY:
				route.Gateway = net.IP(a.Value)

			case syscall.RTA_OIF:
				oif := *(*uint32)(unsafe.Pointer(&a.Value[0]))
				iface, err := net.InterfaceByIndex(int(oif))
				if err != nil {
				}

				route.Iface = iface

			case syscall.RTA_PRIORITY:
			}
		}

		routes = append(routes, route)
	}

	return routes, nil
}

