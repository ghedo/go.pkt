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

// Provides encoding and decoding for SLL (Linux cooked mode) packets.
package sll

import "net"

import "github.com/ghedo/go.pkt/packet"
import "github.com/ghedo/go.pkt/packet/eth"

type Packet struct {
	Type        Type
	AddrType    uint16           `string:"atype"`
	AddrLen     uint16           `string:"alen"`
	SrcAddr     net.HardwareAddr `string:"src"`
	EtherType   eth.EtherType
	pkt_payload packet.Packet    `cmp:"skip" string:"skip"`
}

type Type uint16

const (
	Host      Type = 0
	Broadcast Type = 1
	Multicast Type = 2
	OtherHost Type = 3
	Outgoing  Type = 4
)

func Make() *Packet {
	return &Packet{
		Type: Host,
		AddrType: 2,
		AddrLen: 6,
	}
}

func (p *Packet) GetType() packet.Type {
	return packet.SLL
}

func (p *Packet) GetLength() uint16 {
	if p.pkt_payload != nil {
		return p.pkt_payload.GetLength() + 16
	}

	return p.AddrLen + 16
}

func (p *Packet) Equals(other packet.Packet) bool {
	return packet.Compare(p, other)
}

func (p *Packet) Answers(other packet.Packet) bool {
	return false
}

func (p *Packet) Pack(buf *packet.Buffer) error {
	buf.WriteN(p.Type)
	buf.WriteN(p.AddrType)
	buf.WriteN(p.AddrLen)
	buf.WriteN(p.SrcAddr)

	for i := 0; i < 8 - int(p.AddrLen); i++ {
		buf.WriteN(uint8(0x00))
	}

	buf.WriteN(p.EtherType)

	return nil
}

func (p *Packet) Unpack(buf *packet.Buffer) error {
	buf.ReadN(&p.Type)
	buf.ReadN(&p.AddrType)
	buf.ReadN(&p.AddrLen)

	p.SrcAddr = net.HardwareAddr(buf.Next(int(p.AddrLen)))
	buf.Next(8 - int(p.AddrLen))

	buf.ReadN(&p.EtherType)

	return nil
}

func (p *Packet) Payload() packet.Packet {
	return p.pkt_payload
}

func (p *Packet) GuessPayloadType() packet.Type {
	return eth.EtherTypeToType(p.EtherType)
}

func (p *Packet) SetPayload(pl packet.Packet) error {
	p.pkt_payload = pl
	p.EtherType   = eth.TypeToEtherType(pl.GetType())

	return nil
}

func (p *Packet) InitChecksum(csum uint32) {
}

func (p *Packet) String() string {
	return packet.Stringify(p)
}

func (t Type) String() string {
	switch t {
	case Host:      return "host"
	case Broadcast: return "broadcast"
	case Multicast: return "multicast"
	case OtherHost: return "other"
	case Outgoing:  return "outgoing"
	default:        return "unknown"
	}
}
