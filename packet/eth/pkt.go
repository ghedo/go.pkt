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

import "net"

import "github.com/ghedo/hype/packet"

type Packet struct {
	DstAddr     net.HardwareAddr `name:"dst"`
	SrcAddr     net.HardwareAddr `name:"src"`
	Type        packet.Type
	Length      uint16
	pkt_payload packet.Packet    `name:"skip"`
}

func Make() *Packet {
	return &Packet{
		DstAddr: make([]byte, 6),
		SrcAddr: make([]byte, 6),
		Type: packet.None,
	}
}

func (p *Packet) GetType() packet.Type {
	return packet.Eth
}

func (p *Packet) GetLength() uint16 {
	if p.Length > 0 && p.Type == packet.LLC {
		return p.Length
	}

	if p.pkt_payload != nil {
		return p.pkt_payload.GetLength() + 14
	}

	return 14
}

func (p *Packet) Pack(raw_pkt *packet.Buffer) error {
	raw_pkt.Write(p.DstAddr)
	raw_pkt.Write(p.SrcAddr)

	var typeorlen uint16
	if p.Type != packet.LLC {
		typeorlen = p.Type.ToEtherType()
	} else {
		typeorlen = p.Length
	}

	raw_pkt.WriteI(typeorlen)

	return nil
}

func (p *Packet) Unpack(raw_pkt *packet.Buffer) error {
	p.DstAddr = net.HardwareAddr(raw_pkt.Next(6))
	p.SrcAddr = net.HardwareAddr(raw_pkt.Next(6))

	var typeorlen uint16
	raw_pkt.ReadI(&typeorlen)

	if typeorlen < 0x0600 {
		p.Length = typeorlen
		p.Type   = packet.LLC
	} else {
		p.Length = 0
		p.Type   = packet.EtherType(typeorlen)
	}

	return nil
}

func (p *Packet) Payload() packet.Packet {
	return p.pkt_payload
}

func (p *Packet) PayloadType() packet.Type {
	return p.Type
}

func (p *Packet) SetPayload(pl packet.Packet) error {
	p.pkt_payload = pl
	p.Type        = pl.GetType()
	p.Length     += pl.GetLength()

	return nil
}

func (p *Packet) InitChecksum(csum uint32) {
}

func (p *Packet) String() string {
	return packet.Stringify(p)
}
