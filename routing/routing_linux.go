/*
 * Network packet analysis framework.
 *
 * Copyright (c) 2014, Alessandro Ghedini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package routing

import "fmt"
import "net"
import "sort"
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
		return nil, fmt.Errorf("Could not parse messages: %s", err)
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

// Return the route that matches the given destination address.
func RouteTo(dst net.IP) (*Route, error) {
	var def *Route

	routes, err := Routes()
	if err != nil {
		return nil, fmt.Errorf("Could not get routes: %s", err)
	}

	sort.Sort(route_slice(routes))

	for _, r := range routes {
		if r.Default &&
			r.Iface != nil &&
			r.Iface.Flags&net.FlagLoopback == 0 {
			def = r
			continue
		}

		if r.DstNet != nil &&
			r.DstNet.Contains(dst) {
			return r, nil
		}
	}

	return def, nil
}
