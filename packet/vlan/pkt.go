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

// Provides encoding and decoding for VLAN packets.
package vlan

import "github.com/ghedo/go.pkt/packet"
import "github.com/ghedo/go.pkt/packet/eth"

type Packet struct {
    Priority     uint8         `string:"prio"`
    DropEligible bool          `string:"drop"`
    VLAN         uint16
    Type         eth.EtherType
    pkt_payload  packet.Packet `cmp:"skip" string:"skip"`
}

func Make() *Packet {
    return &Packet{ }
}

func (p *Packet) GetType() packet.Type {
    return packet.VLAN
}

func (p *Packet) GetLength() uint16 {
    if p.pkt_payload != nil {
        return p.pkt_payload.GetLength() + 4
    }

    return 4
}

func (p *Packet) Equals(other packet.Packet) bool {
    return packet.Compare(p, other)
}

func (p *Packet) Answers(other packet.Packet) bool {
    if other == nil {
        return false
    }

    if  other.GetType() == packet.VLAN &&
        p.VLAN != other.(*Packet).VLAN {
        return false
    }

    if p.Payload() != nil {
        return p.Payload().Answers(other.Payload())
    }

    return true
}

func (p *Packet) Pack(buf *packet.Buffer) error {
    tci := uint16(p.Priority) << 13 | p.VLAN
    if p.DropEligible {
        tci |= 0x10
    }

    buf.WriteN(tci)
    buf.WriteN(p.Type)

    return nil
}

func (p *Packet) Unpack(buf *packet.Buffer) error {
    var tci uint16
    buf.ReadN(&tci)

    p.Priority     = (uint8(tci >> 8) & 0xE0) >> 5
    p.DropEligible = uint8(tci) & 0x10 != 0
    p.VLAN         = tci & 0x0FFF

    buf.ReadN(&p.Type)

    return nil
}

func (p *Packet) Payload() packet.Packet {
    return p.pkt_payload
}

func (p *Packet) GuessPayloadType() packet.Type {
    return eth.EtherTypeToType(p.Type)
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
