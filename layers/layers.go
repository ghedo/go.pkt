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

// Provides utility functions for encoding and decoding packets to/from binary
// data. Differently from the basic "packet" interface, this can encode and
// decode complete "stacks" of packets (e.g. ethernet -> ipv4 -> udp), instead
// of manipulating single ones.
package util

import "github.com/ghedo/hype/packet"

import "github.com/ghedo/hype/packet/arp"
import "github.com/ghedo/hype/packet/eth"
import "github.com/ghedo/hype/packet/icmpv4"
import "github.com/ghedo/hype/packet/icmpv6"
import "github.com/ghedo/hype/packet/ipv4"
import "github.com/ghedo/hype/packet/ipv6"
import "github.com/ghedo/hype/packet/llc"
import "github.com/ghedo/hype/packet/raw"
import "github.com/ghedo/hype/packet/sll"
import "github.com/ghedo/hype/packet/snap"
import "github.com/ghedo/hype/packet/tcp"
import "github.com/ghedo/hype/packet/udp"
import "github.com/ghedo/hype/packet/vlan"

// Compose packets into a chain and update their values (e.g. length, payload
// protocol) accordingly.
func Compose(pkts ...packet.Packet) (packet.Packet, error) {
	prev_pkt := packet.Packet(nil)

	for _, p := range pkts {
		if prev_pkt != nil {
			err := prev_pkt.SetPayload(p)
			if err != nil {
				return nil, err
			}
		}

		prev_pkt = p
	}

	return pkts[0], nil
}

// Pack packets into their binary form. This will stack the packets before
// encoding them (see the Compose() method) and also calculate the checksums.
func Pack(pkts ...packet.Packet) ([]byte, error) {
	var buf packet.Buffer

	base_pkt, err := Compose(pkts...)
	if err != nil {
		return nil, err
	}

	for cur_pkt := base_pkt; cur_pkt != nil; cur_pkt = cur_pkt.Payload() {
		buf.Checkpoint()

		err := cur_pkt.Pack(&buf)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// Unpack the given byte slice into the packet list supplied. Note that this
// will not check whether the packet types provided match the raw data. If the
// packet types to be decoded are unknown, UnpackAll() should be used instead.
func Unpack(buf []byte, pkts ...packet.Packet) (packet.Packet, error) {
	var raw_pkt packet.Buffer
	raw_pkt.Init(buf)

	prev_pkt := packet.Packet(nil)

	for _, p := range pkts {
		if raw_pkt.Len() <= 0 {
			break
		}

		raw_pkt.Checkpoint()

		err := p.Unpack(&raw_pkt)
		if err != nil {
			return nil, err
		}

		if prev_pkt != nil {
			prev_pkt.SetPayload(p)
		}

		if p.GetType().IsPayload() {
			break
		}

		prev_pkt = p
	}

	return pkts[0], nil
}

// Unpack the given byte slice into a list of arbitrary packet types. It will
// extract packet type information from the binary data and use it to allocate
// new packet accordingly. Note that given the memory allocations performed,
// thsi may be slower then the Unpack() method.
func UnpackAll(buf []byte, link_type packet.Type) ([]packet.Packet, error) {
	var raw_pkt packet.Buffer
	raw_pkt.Init(buf)

	pkts     := []packet.Packet{}
	prev_pkt := packet.Packet(nil)

	for {
		var p packet.Packet

		if raw_pkt.Len() <= 0 {
			break
		}

		switch link_type {
		case packet.ARP:    p = &arp.Packet{}
		case packet.Eth:    p = &eth.Packet{}
		case packet.ICMPv4: p = &icmpv4.Packet{}
		case packet.ICMPv6: p = &icmpv6.Packet{}
		case packet.IPv4:   p = &ipv4.Packet{}
		case packet.IPv6:   p = &ipv6.Packet{}
		case packet.LLC:    p = &llc.Packet{}
		case packet.SLL:    p = &sll.Packet{}
		case packet.SNAP:   p = &snap.Packet{}
		case packet.TCP:    p = &tcp.Packet{}
		case packet.UDP:    p = &udp.Packet{}
		case packet.VLAN:   p = &vlan.Packet{}
		default:            p = &raw.Packet{}
		}

		if p == nil {
			break
		}

		raw_pkt.Checkpoint()

		err := p.Unpack(&raw_pkt)
		if err != nil {
			return nil, err
		}

		pkts = append(pkts, p)

		if prev_pkt != nil {
			prev_pkt.SetPayload(p)
		}

		if p.GetType().IsPayload() {
			break
		}

		prev_pkt  = p
		link_type = p.PayloadType()
	}

	return pkts, nil
}
