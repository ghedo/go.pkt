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

// Provides encoding and decoding for Ethernet (both EthernetII and 802.3)
// packets.
package eth

import "fmt"
import "net"

import "github.com/ghedo/hype/packet"

type Packet struct {
	DstAddr     net.HardwareAddr `string:"dst"`
	SrcAddr     net.HardwareAddr `string:"src"`
	Type        EtherType
	Length      uint16
	pkt_payload packet.Packet    `string:"skip"`
}

type EtherType uint16

const (
	None EtherType = 0x0000
	ARP            = 0x0806
	IPv4           = 0x0800
	IPv6           = 0x86dd
	LLC            = 0x0001  /* pseudo ethertype */
	LLDP           = 0x088cc
	QinQ           = 0x88a8
	TRILL          = 0x22f3
	VLAN           = 0x8100
	WoL            = 0x0842
)

func Make() *Packet {
	return &Packet{
		DstAddr: make([]byte, 6),
		SrcAddr: make([]byte, 6),
		Length:  14,
	}
}

func (p *Packet) Equals(other packet.Packet) bool {
	return packet.Compare(p, other)
}

func (p *Packet) Answers(other packet.Packet) bool {
	if other == nil || other.GetType() != packet.Eth {
		return false
	}

	if p.Type != other.(*Packet).Type {
		return false
	}

	if p.Payload() != nil {
		return p.Payload().Answers(other.Payload())
	}

	return true
}

func (p *Packet) GetType() packet.Type {
	return packet.Eth
}

func (p *Packet) GetLength() uint16 {
	if p.pkt_payload != nil {
		return p.pkt_payload.GetLength() + 14
	}

	return 14
}

func (p *Packet) Pack(buf *packet.Buffer) error {
	buf.Write(p.DstAddr)
	buf.Write(p.SrcAddr)

	if p.Type != LLC {
		buf.WriteI(p.Type)
	} else {
		buf.WriteI(p.Length)
	}

	return nil
}

func (p *Packet) Unpack(buf *packet.Buffer) error {
	p.DstAddr = net.HardwareAddr(buf.Next(6))
	p.SrcAddr = net.HardwareAddr(buf.Next(6))

	buf.ReadI(&p.Type)

	if p.Type < 0x0600 {
		p.Length = uint16(p.Type)
		p.Type   = LLC
	}

	return nil
}

func (p *Packet) Payload() packet.Packet {
	return p.pkt_payload
}

func (p *Packet) GuessPayloadType() packet.Type {
	return EtherTypeToType(p.Type)
}

func (p *Packet) SetPayload(pl packet.Packet) error {
	p.pkt_payload = pl
	p.Type        = TypeToEtherType(pl.GetType())

	if p.Type < 0x0600 {
		p.Length += pl.GetLength()
	}

	return nil
}

func (p *Packet) InitChecksum(csum uint32) {
}

func (p *Packet) String() string {
	return packet.Stringify(p)
}

var ethertype_to_type_map = map[EtherType]packet.Type{
	None:  packet.None,
	ARP:   packet.ARP,
	IPv4:  packet.IPv4,
	IPv6:  packet.IPv6,
	LLC:   packet.LLC,
	LLDP:  packet.LLDP,
	VLAN:  packet.VLAN,
	QinQ:  packet.VLAN,
	TRILL: packet.TRILL,
	WoL:   packet.WoL,
}

// Create a new Type from the given EtherType.
func EtherTypeToType(ethertype EtherType) packet.Type {
	for e, t := range ethertype_to_type_map {
		if e == ethertype {
			return t
		}
	}

	return packet.Raw
}

// Convert the Type to the corresponding EtherType.
func TypeToEtherType(pkttype packet.Type) EtherType {
	for e, t := range ethertype_to_type_map {
		if t == pkttype {
			return e
		}
	}

	return None
}

func (t EtherType) String() string {
	switch t {
	case ARP:   return "ARP"
	case IPv4:  return "IPv4"
	case IPv6:  return "IPv6"
	case LLC:   return "LLC"
	case LLDP:  return "LLDP"
	case None:  return "None"
	case QinQ:  return "QinQ"
	case TRILL: return "TRILL"
	case VLAN:  return "VLAN"
	case WoL:   return "WoL"
	default:    return fmt.Sprintf("0x%x", uint16(t))
	}
}
