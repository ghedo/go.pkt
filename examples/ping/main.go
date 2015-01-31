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

package main

import "log"
import "math/rand"
import "net"
import "time"

import "github.com/docopt/docopt-go"

import "github.com/ghedo/go.pkt/capture"
import "github.com/ghedo/go.pkt/capture/pcap"

import "github.com/ghedo/go.pkt/packet/arp"
import "github.com/ghedo/go.pkt/packet/eth"
import "github.com/ghedo/go.pkt/packet/icmpv4"
import "github.com/ghedo/go.pkt/packet/ipv4"

import "github.com/ghedo/go.pkt/network"
import "github.com/ghedo/go.pkt/routing"

func main() {
	log.SetFlags(0)

	usage := `Usage: ping <addr>

Ping the given IP address.`

	args, err := docopt.Parse(usage, nil, true, "", false)
	if err != nil {
		log.Fatalf("Invalid arguments: %s", err)
	}

	addr    := args["<addr>"].(string)
	addr_ip := net.ParseIP(addr)
	timeout := 5 * time.Second

	route, err := routing.RouteTo(addr_ip)
	if err != nil {
		log.Fatalf("Error: %s", err)
	}

	if route == nil {
		log.Println("No route found")
	}

	c, err := pcap.Open(route.Iface.Name)
	if err != nil {
		log.Fatalf("Error opening interface: %s", err)
	}
	defer c.Close()

	err = c.Activate()
	if err != nil {
		log.Fatalf("Error activating source: %s", err)
	}

	eth_pkt := eth.Make()
	eth_pkt.SrcAddr = route.Iface.HardwareAddr

	if route.Default {
		eth_pkt.DstAddr = ResolveARP(c, timeout, route, route.Gateway)
	} else {
		eth_pkt.DstAddr = ResolveARP(c, timeout, route, addr_ip)
	}

	ipv4_pkt := ipv4.Make()
	ipv4_pkt.SrcAddr = route.PrefSrc
	ipv4_pkt.DstAddr = addr_ip

	icmp_pkt := icmpv4.Make()
	icmp_pkt.Type = icmpv4.EchoRequest
	icmp_pkt.Seq = 0
	icmp_pkt.Id = uint16(rand.Intn(65535))

	_, err = network.SendRecv(c, timeout, eth_pkt, ipv4_pkt, icmp_pkt)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("ping")
}

func ResolveARP(c capture.Handle, t time.Duration, r *routing.Route, addr net.IP) net.HardwareAddr {
	eth_pkt := eth.Make()
	eth_pkt.SrcAddr = r.Iface.HardwareAddr
	eth_pkt.DstAddr, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")

	arp_pkt := arp.Make()
	arp_pkt.HWSrcAddr = r.Iface.HardwareAddr
	arp_pkt.HWDstAddr, _ = net.ParseMAC("00:00:00:00:00:00")
	arp_pkt.ProtoSrcAddr = r.PrefSrc
	arp_pkt.ProtoDstAddr = addr

	pkt, err := network.SendRecv(c, t, eth_pkt, arp_pkt)
	if err != nil {
		log.Fatal(err)
	}

	return pkt.Payload().(*arp.Packet).HWSrcAddr
}
