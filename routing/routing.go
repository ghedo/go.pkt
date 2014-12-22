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

// Provides network routing information about the system. It can either return
// all available routes or select a specific route depending on a destination
// address.
package routing

import "fmt"
import "net"
import "sort"
import "strings"

type Route struct {
	Default bool
	SrcNet  *net.IPNet
	DstNet  *net.IPNet
	Gateway net.IP
	Iface   *net.Interface
	PrefSrc net.IP
}

type route_slice []*Route

func (r route_slice) Len() int {
	return len(r)
}

func (r route_slice) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r route_slice) Less(i, j int) bool {
	a := r[i]
	b := r[j]

	if a.Default {
		return true
	}

	if b.Default {
		return false
	}

	a_len, _ := a.DstNet.Mask.Size()
	b_len, _ := b.DstNet.Mask.Size()
	if a_len < b_len {
		return false
	}

	return true
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
		   r.Iface.Flags & net.FlagLoopback == 0 {
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

func (r *Route) String() string {
	var parts []string

	if r.Default {
		parts = append(parts, "default")
	} else if r.DstNet != nil {
		parts = append(parts, r.DstNet.String())
	}

	if r.SrcNet != nil {
		src := fmt.Sprintf("from %s", r.DstNet.String())
		parts = append(parts, src)
	}

	if r.Gateway != nil {
		gateway := fmt.Sprintf("via %s", r.Gateway.String())
		parts = append(parts, gateway)
	}

	if r.Iface != nil {
		iface := fmt.Sprintf("dev %s", r.Iface.Name)
		parts = append(parts, iface)
	}


	if r.PrefSrc != nil {
		prefsrc := fmt.Sprintf("src %s", r.PrefSrc.String())
		parts = append(parts, prefsrc)
	}

	return strings.Join(parts, " ")
}
