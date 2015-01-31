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

// Provides encoding and decoding for UDP packets.
package udp

import "github.com/ghedo/go.pkt/packet"
import "github.com/ghedo/go.pkt/packet/ipv4"

type Packet struct {
	SrcPort     uint16        `string:"sport"`
	DstPort     uint16        `string:"dport"`
	Length      uint16        `string:"len"`
	Checksum    uint16        `string:"sum"`
	csum_seed   uint32        `cmp:"skip" string:"skip"`
	pkt_payload packet.Packet `cmp:"skip" string:"skip"`
}

func Make() *Packet {
	return &Packet{
		Length: 8,
	}
}

func (p *Packet) GetType() packet.Type {
	return packet.UDP
}

func (p *Packet) GetLength() uint16 {
	if p.pkt_payload != nil {
		return p.pkt_payload.GetLength() + 8
	}

	return 8
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

func (p *Packet) Pack(buf *packet.Buffer) error {
	buf.WriteN(p.SrcPort)
	buf.WriteN(p.DstPort)
	buf.WriteN(p.Length)

	if p.csum_seed != 0 {
		p.Checksum =
		  ipv4.CalculateChecksum(buf.LayerBytes(), p.csum_seed)
	}

	buf.WriteN(p.Checksum)

	return nil
}

func (p *Packet) Unpack(buf *packet.Buffer) error {
	buf.ReadN(&p.SrcPort)
	buf.ReadN(&p.DstPort)
	buf.ReadN(&p.Length)
	buf.ReadN(&p.Checksum)

	return nil
}

func (p *Packet) Payload() packet.Packet {
	return p.pkt_payload
}

func (p *Packet) GuessPayloadType() packet.Type {
	return packet.Raw
}

func (p *Packet) SetPayload(pl packet.Packet) error {
	p.pkt_payload = pl
	p.Length      = p.GetLength()

	return nil
}

func (p *Packet) InitChecksum(csum uint32) {
	p.csum_seed = csum
}

func (p *Packet) String() string {
	return packet.Stringify(p)
}
