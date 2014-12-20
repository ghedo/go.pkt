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

// Provides encoding and decoding for TCP packets.
package tcp

import "strings"

import "github.com/ghedo/hype/packet"
import "github.com/ghedo/hype/packet/ipv4"

type Packet struct {
	SrcPort     uint16        `string:"sport"`
	DstPort     uint16        `string:"dport"`
	Seq         uint32
	Ack         uint32
	DataOff     uint8         `string:"off"`
	NS          bool
	Flags       Flags
	WindowSize  uint16        `string:"win"`
	Checksum    uint16        `string:"sum"`
	Urgent      uint16        `string:"urg"`
	csum_seed   uint32        `string:"skip"`
	pkt_payload packet.Packet `string:"skip"`
}

type Flags uint16

const (
	Syn Flags = 1<<1
	Fin       = 1<<2
	Rst       = 1<<3
	PSH       = 1<<4
	Ack       = 1<<5
	Urg       = 1<<6
	ECE       = 1<<7
	Cwr       = 1<<8
	NS        = 1<<9
)

func Make() *Packet {
	return &Packet{
		DataOff: 5,
	}
}

func (p *Packet) GetType() packet.Type {
	return packet.TCP
}

func (p *Packet) GetLength() uint16 {
	if p.pkt_payload != nil {
		return p.pkt_payload.GetLength() + uint16(p.DataOff) * 4
	}

	return uint16(p.DataOff) * 4
}

func (p *Packet) Equals(other packet.Packet) bool {
	return packet.Compare(p, other)
}

func (p *Packet) Answers(other packet.Packet) bool {
	if other == nil || other.GetType() != packet.TCP {
		return false
	}

	if p.SrcPort != other.(*Packet).DstPort ||
	   p.DstPort != other.(*Packet).SrcPort {
		return false
	}

	return true
}

func (p *Packet) Pack(raw_pkt *packet.Buffer) error {
	raw_pkt.WriteI(p.SrcPort)
	raw_pkt.WriteI(p.DstPort)
	raw_pkt.WriteI(p.Seq)
	raw_pkt.WriteI(p.Ack)

	flags := uint16(p.DataOff) << 12

	if p.Flags & Fin != 0 {
		flags |= 0x0001
	}

	if p.Flags & Syn != 0 {
		flags |= 0x0002
	}

	if p.Flags & Rst != 0 {
		flags |= 0x0004
	}

	if p.Flags & PSH != 0 {
		flags |= 0x0008
	}

	if p.Flags & Ack != 0 {
		flags |= 0x0010
	}

	if p.Flags & Urg != 0 {
		flags |= 0x0020
	}

	if p.Flags & ECE != 0 {
		flags |= 0x0040
	}

	if p.Flags & Cwr != 0 {
		flags |= 0x0080
	}

	if p.Flags & NS != 0 {
		flags |= 0x0100
	}

	raw_pkt.WriteI(flags)

	raw_pkt.WriteI(p.WindowSize)
	raw_pkt.WriteI(uint16(0x0000))
	raw_pkt.WriteI(p.Urgent)

	if p.csum_seed != 0 {
		p.Checksum =
		  ipv4.CalculateChecksum(raw_pkt.BytesOff(), p.csum_seed)
	}

	raw_pkt.PutUint16Off(16, p.Checksum)

	return nil
}

func (p *Packet) Unpack(raw_pkt *packet.Buffer) error {
	raw_pkt.ReadI(&p.SrcPort)
	raw_pkt.ReadI(&p.DstPort)
	raw_pkt.ReadI(&p.Seq)
	raw_pkt.ReadI(&p.Ack)

	var offns uint8
	raw_pkt.ReadI(&offns)

	p.DataOff = offns >> 4

	if offns & 0x01 != 0 {
		p.Flags |= NS
	}

	var flags uint8
	raw_pkt.ReadI(&flags)

	if flags & 0x01 != 0 {
		p.Flags |= Fin
	}

	if flags & 0x02 != 0 {
		p.Flags |= Syn
	}

	if flags & 0x04 != 0 {
		p.Flags |= Rst
	}

	if flags & 0x08 != 0 {
		p.Flags |= PSH
	}

	if flags & 0x10 != 0 {
		p.Flags |= Ack
	}

	if flags & 0x20 != 0 {
		p.Flags |= Urg
	}

	if flags & 0x40 != 0 {
		p.Flags |= ECE
	}

	if flags & 0x80 != 0 {
		p.Flags |= Cwr
	}

	raw_pkt.ReadI(&p.WindowSize)
	raw_pkt.ReadI(&p.Checksum)
	raw_pkt.ReadI(&p.Urgent)

	if int(p.DataOff * 4) > raw_pkt.LenOff() {
		/* TODO: Options */
	}

	return nil
}

func (p *Packet) Payload() packet.Packet {
	return p.pkt_payload
}

func (p *Packet) PayloadType() packet.Type {
	if p.pkt_payload != nil {
		return p.pkt_payload.GetType()
	}

	return packet.None
}

func (p *Packet) SetPayload(pl packet.Packet) error {
	p.pkt_payload = pl

	return nil
}

func (p *Packet) InitChecksum(csum uint32) {
	p.csum_seed = csum
}

func (p *Packet) String() string {
	return packet.Stringify(p)
}

func (f Flags) String() string {
	var flags []string

	if f & Fin != 0 {
		flags = append(flags, "fin")
	}

	if f & Syn != 0 {
		flags = append(flags, "syn")
	}

	if f & Rst != 0 {
		flags = append(flags, "rst")
	}

	if f & PSH != 0 {
		flags = append(flags, "psh")
	}

	if f & Ack != 0 {
		flags = append(flags, "ack")
	}

	if f & Urg != 0 {
		flags = append(flags, "urg")
	}

	if f & ECE != 0 {
		flags = append(flags, "ece")
	}

	if f & Cwr != 0 {
		flags = append(flags, "cwr")
	}

	if f & NS != 0 {
		flags = append(flags, "ns")
	}

	return strings.Join(flags, "|")
}
