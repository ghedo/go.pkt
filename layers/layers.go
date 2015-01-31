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
// decode complete "stacks" of packets, instead of manipulating single ones.
package layers

import "github.com/ghedo/go.pkt/packet"

import "github.com/ghedo/go.pkt/packet/arp"
import "github.com/ghedo/go.pkt/packet/eth"
import "github.com/ghedo/go.pkt/packet/icmpv4"
import "github.com/ghedo/go.pkt/packet/icmpv6"
import "github.com/ghedo/go.pkt/packet/ipv4"
import "github.com/ghedo/go.pkt/packet/ipv6"
import "github.com/ghedo/go.pkt/packet/llc"
import "github.com/ghedo/go.pkt/packet/radiotap"
import "github.com/ghedo/go.pkt/packet/raw"
import "github.com/ghedo/go.pkt/packet/sll"
import "github.com/ghedo/go.pkt/packet/snap"
import "github.com/ghedo/go.pkt/packet/tcp"
import "github.com/ghedo/go.pkt/packet/udp"
import "github.com/ghedo/go.pkt/packet/vlan"

// Compose packets into a chain and update their values (e.g. length, payload
// protocol) accordingly.
func Compose(pkts ...packet.Packet) (packet.Packet, error) {
	next_pkt := packet.Packet(nil)

	for i := len(pkts) - 1; i >= 0; i-- {
		if next_pkt != nil {
			err := pkts[i].SetPayload(next_pkt)
			if err != nil {
				return nil, err
			}
		}

		next_pkt = pkts[i]
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

	tot_len := int(base_pkt.GetLength())

	buf.Init(make([]byte, tot_len))

	for i := len(pkts) - 1; i >= 0; i-- {
		cur_pkt := pkts[i]
		cur_len := int(cur_pkt.GetLength())

		buf.SetOffset(tot_len - cur_len)
		buf.NewLayer()

		err := cur_pkt.Pack(&buf)
		if err != nil {
			return nil, err
		}
	}

	buf.SetOffset(0)

	return buf.Bytes(), nil
}

// Unpack the given byte slice into the packet list supplied. Note that this
// will not check whether the packet types provided match the raw data. If the
// packet types to be decoded are unknown, UnpackAll() should be used instead.
//
// Note that unpacking is done without copying the input slice, which means that
// if the slice is modifed, it may affect the packets that where unpacked from
// it. If you can't guarantee that the data slice won't change, you'll need to
// copy it and pass the copy to Unpack().
func Unpack(buf []byte, pkts ...packet.Packet) (packet.Packet, error) {
	var b packet.Buffer
	b.Init(buf)

	prev_pkt := packet.Packet(nil)

	for _, p := range pkts {
		if b.Len() <= 0 {
			break
		}

		b.NewLayer()

		err := p.Unpack(&b)
		if err != nil {
			return nil, err
		}

		if prev_pkt != nil {
			prev_pkt.SetPayload(p)
		}

		if p.GuessPayloadType() == packet.None {
			break
		}

		prev_pkt = p
	}

	return pkts[0], nil
}


// Recursively unpack the given byte slice into a packet. The link_type argument
// must specify the type of the first layer in the input data, successive layers
// will be detected automatically.
//
// Note that unpacking is done without copying the input slice, which means that
// if the slice is modifed, it may affect the packets that where unpacked from
// it. If you can't guarantee that the data slice won't change, you'll need to
// copy it and pass the copy to UnpackAll().
func UnpackAll(buf []byte, link_type packet.Type) (packet.Packet, error) {
	var b packet.Buffer
	b.Init(buf)

	first_pkt := packet.Packet(nil)
	prev_pkt  := packet.Packet(nil)

	for link_type != packet.None {
		var p packet.Packet

		if b.Len() <= 0 {
			break
		}

		switch link_type {
		case packet.ARP:      p = &arp.Packet{}
		case packet.Eth:      p = &eth.Packet{}
		case packet.ICMPv4:   p = &icmpv4.Packet{}
		case packet.ICMPv6:   p = &icmpv6.Packet{}
		case packet.IPv4:     p = &ipv4.Packet{}
		case packet.IPv6:     p = &ipv6.Packet{}
		case packet.LLC:      p = &llc.Packet{}
		case packet.RadioTap: p = &radiotap.Packet{}
		case packet.SLL:      p = &sll.Packet{}
		case packet.SNAP:     p = &snap.Packet{}
		case packet.TCP:      p = &tcp.Packet{}
		case packet.UDP:      p = &udp.Packet{}
		case packet.VLAN:     p = &vlan.Packet{}
		default:              p = &raw.Packet{}
		}

		if p == nil {
			break
		}

		b.NewLayer()

		err := p.Unpack(&b)
		if err != nil {
			return nil, err
		}

		if prev_pkt != nil {
			prev_pkt.SetPayload(p)
		} else {
			first_pkt = p
		}

		prev_pkt  = p
		link_type = p.GuessPayloadType()
	}

	return first_pkt, nil
}

// Return the first layer of the given type in the packet. If no suitable layer
// is found, return nil.
func FindLayer(p packet.Packet, layer packet.Type) packet.Packet {
	switch {
	case p == nil:
		return nil

	case p.GetType() == layer:
		return p

	default:
		return FindLayer(p.Payload(), layer)
	}
}
