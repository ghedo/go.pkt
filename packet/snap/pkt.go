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

// Provides encoding and decoding for SNAP packets.
package snap

import "github.com/ghedo/hype/packet"
import "github.com/ghedo/hype/packet/eth"

type Packet struct {
	OUI         [3]byte
	Type        eth.EtherType

	pkt_payload packet.Packet `cmp:"skip" string:"skip"`
}

func Make() *Packet {
	return &Packet{ }
}

func (p *Packet) GetType() packet.Type {
	return packet.SNAP
}

func (p *Packet) GetLength() uint16 {
	if p.pkt_payload != nil {
		return p.pkt_payload.GetLength() + 5
	}

	return 5
}

func (p *Packet) Equals(other packet.Packet) bool {
	return packet.Compare(p, other)
}

func (p *Packet) Answers(other packet.Packet) bool {
	return false
}

func (p *Packet) Pack(buf *packet.Buffer) error {
	buf.WriteN(p.OUI)
	buf.WriteN(p.Type)

	return nil
}

func (p *Packet) Unpack(buf *packet.Buffer) error {
	buf.ReadN(&p.OUI)
	buf.ReadN(&p.Type)

	return nil
}

func (p *Packet) Payload() packet.Packet {
	return p.pkt_payload
}

func (p *Packet) GuessPayloadType() packet.Type {
	if p.OUI[0] == 0x00 && p.OUI[1] == 0x00 && p.OUI[2] == 0x00 {
		return eth.EtherTypeToType(p.Type)
	} else {
		return packet.Raw
	}
}

func (p *Packet) SetPayload(pl packet.Packet) error {
	p.pkt_payload = pl
	p.Type        = eth.TypeToEtherType(pl.GetType())

	return nil
}

func (p *Packet) InitChecksum(csum uint32) {
}

func (p *Packet) String() string {
	return packet.Stringify(p)
}
