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

// Provides encoding and decoding for LLC (802.2 Logical Link Control) packets.
package llc

import "github.com/ghedo/hype/packet"

type Packet struct {
	DSAP        uint8
	SSAP        uint8
	Control     uint16        `string:"ctrl"`

	pkt_payload packet.Packet `string:"skip"`
}

func Make() *Packet {
	return &Packet{
	}
}

func (p *Packet) GetType() packet.Type {
	return packet.LLC
}

func (p *Packet) GetLength() uint16 {
	if p.pkt_payload != nil {
		return p.pkt_payload.GetLength() + 2
	}

	return 2
}

func (p *Packet) Equals(other packet.Packet) bool {
	return packet.Compare(p, other)
}

func (p *Packet) Answers(other packet.Packet) bool {
	return false
}

func (p *Packet) Pack(raw_pkt *packet.Buffer) error {
	raw_pkt.WriteI(p.DSAP)
	raw_pkt.WriteI(p.SSAP)

	if p.Control & 0x1 == 0 || p.Control & 0x3 == 0x1 {
		raw_pkt.WriteI(p.Control)
	} else {
		raw_pkt.WriteI(uint8(p.Control))
	}

	return nil
}

func (p *Packet) Unpack(raw_pkt *packet.Buffer) error {
	raw_pkt.ReadI(&p.DSAP)
	raw_pkt.ReadI(&p.SSAP)

	if raw_pkt.Bytes()[:1][0] & 0x1 == 0 ||
	   raw_pkt.Bytes()[:1][0] & 0x3 == 0x1 {
		raw_pkt.ReadI(&p.Control)
	} else {
		var ctrl uint8
		raw_pkt.ReadI(&ctrl)
		p.Control = uint16(ctrl)
	}

	return nil
}

func (p *Packet) Payload() packet.Packet {
	return p.pkt_payload
}

func (p *Packet) GuessPayloadType() packet.Type {
	if p.DSAP == 0xaa && p.SSAP == 0xaa {
		return packet.SNAP
	}

	return packet.None
}

func (p *Packet) SetPayload(pl packet.Packet) error {
	p.pkt_payload = pl

	return nil
}

func (p *Packet) InitChecksum(csum uint32) {
}

func (p *Packet) String() string {
	return packet.Stringify(p)
}
