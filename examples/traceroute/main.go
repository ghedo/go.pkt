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
import "math"
import "math/rand"
import "net"

import "github.com/docopt/docopt-go"

import "github.com/ghedo/hype/capture/pcap"
import "github.com/ghedo/hype/layers"
import "github.com/ghedo/hype/routing"

import "github.com/ghedo/hype/packet"
import "github.com/ghedo/hype/packet/eth"
import "github.com/ghedo/hype/packet/icmpv4"
import "github.com/ghedo/hype/packet/ipv4"
import "github.com/ghedo/hype/packet/raw"
import "github.com/ghedo/hype/packet/tcp"
import "github.com/ghedo/hype/packet/udp"

func main() {
	log.SetFlags(0)

	usage := `Usage: traceroute (--icmp | --udp | --tcp ) <addr>

Options:
  --icmp  Use ICMP packets.
  --udp   Use UDP packets.
  --tcp   Use TCP packets.`

	args, err := docopt.Parse(usage, nil, true, "", false)
	if err != nil {
		log.Fatalf("Invalid arguments: %s", err)
	}

	addr    := args["<addr>"].(string)
	addr_ip := net.ParseIP(addr)

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

	err = c.Activate()
	if err != nil {
		log.Fatalf("Error activating source: %s", err)
	}

	eth_pkt := eth.Make()
	eth_pkt.SrcAddr = route.Iface.HardwareAddr
	/* TODO: resolve route.Gateway via ARP */
	eth_pkt.DstAddr, _ = net.ParseMAC("00:21:96:6e:f0:70")

	ipv4_pkt := ipv4.Make()
	ipv4_pkt.SrcAddr = route.PrefSrc
	ipv4_pkt.DstAddr = addr_ip
	ipv4_pkt.Id      = uint16(rand.Intn(math.MaxUint16))
	ipv4_pkt.TTL     = 1

	var payload_pkt packet.Packet

	if args["--icmp"].(bool) {
		icmp_pkt := icmpv4.Make()
		icmp_pkt.Type = icmpv4.EchoRequest
		icmp_pkt.Id   = uint16(rand.Intn(math.MaxUint16))
		icmp_pkt.Seq  = 1

		payload_pkt = icmp_pkt
	}

	if args["--udp"].(bool) {
		udp_pkt := udp.Make()
		udp_pkt.SrcPort = 49152
		udp_pkt.DstPort = 33434

		raw_pkt := raw.Make()
		raw_pkt.Data = make([]byte, 40 - udp_pkt.GetLength())

		for i := 0; i < len(raw_pkt.Data); i++ {
			raw_pkt.Data[i] = byte(0x40 + (i & 0x3f))
		}

		udp_pkt.SetPayload(raw_pkt)

		payload_pkt = udp_pkt
	}

	if args["--tcp"].(bool) {
		tcp_pkt := tcp.Make()
		tcp_pkt.SrcPort = 49152
		tcp_pkt.DstPort = 80
		tcp_pkt.Flags   = tcp.Syn | tcp.ECE | tcp.Cwr
		tcp_pkt.Seq     = uint32(rand.Intn(math.MaxUint32))
		tcp_pkt.WindowSize = 5840

		raw_pkt := raw.Make()
		raw_pkt.Data = make([]byte, 40 - tcp_pkt.GetLength())

		for i := 0; i < len(raw_pkt.Data); i++ {
			raw_pkt.Data[i] = byte(0x40 + (i & 0x3f))
		}

		tcp_pkt.SetPayload(raw_pkt)

		payload_pkt = tcp_pkt
	}

	for {
		buf, _ := layers.Pack(eth_pkt, ipv4_pkt, payload_pkt)
		err = c.Inject(buf)
		if err != nil {
			log.Fatalf("Error: %s", err)
		}

		for {
			buf, err := c.Capture()
			if err != nil {
				log.Fatalf("Error capturing packet: %s", err)
				break
			}

			rsp_pkt, err := layers.UnpackAll(buf, c.LinkType())
			if err != nil {
				log.Printf("Error: %s\n", err)
			}

			if rsp_pkt.Answers(eth_pkt) {
				ipv4_rsp := rsp_pkt.Payload().(*ipv4.Packet)

				log.Println(ipv4_rsp.SrcAddr)

				if ipv4_rsp.SrcAddr.Equal(addr_ip) {
					return
				}

				break
			}
		}

		ipv4_pkt.TTL++
		ipv4_pkt.Id++

		if ipv4_pkt.TTL > 64 {
			return
		}
	}
}