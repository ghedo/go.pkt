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

// Provides encoding and decoding for ICMPv4 packets.
package icmpv4

import "fmt"

import "github.com/ghedo/hype/packet"
import "github.com/ghedo/hype/packet/ipv4"

type Packet struct {
	Type     Type
	Code     Code
	Checksum uint16 `name:"sum"`
	Id       uint16
	Seq      uint16
}

type Type uint8
type Code uint8

const (
	EchoReply Type = iota
	Reserved1
	Reserved2
	DstUnreachable
	SrcQuench
	RedirectMsg
	Reserved3
	Reserved4
	EchoRequest
	RouterAdv
	RouterSol
	TimeExceeded
	ParamProblem
	Timestamp
	TimestampReply
	InfoRequest
	InfoReply
	AddrMaskRequest
	AddrMaskReply
)

func Make() *Packet {
	return &Packet{ }
}

func (p *Packet) GetType() packet.Type {
	return packet.ICMPv4
}

func (p *Packet) GetLength() uint16 {
	return 8
}

func (p *Packet) Pack(raw_pkt *packet.Buffer) error {
	raw_pkt.WriteI(byte(p.Type))
	raw_pkt.WriteI(byte(p.Code))
	raw_pkt.WriteI(uint16(0x0000))
	raw_pkt.WriteI(p.Id)
	raw_pkt.WriteI(p.Seq)

	p.Checksum = ipv4.CalculateChecksum(raw_pkt.BytesOff(), 0)
	raw_pkt.PutUint16Off(2, p.Checksum)

	return nil
}

func (p *Packet) Unpack(raw_pkt *packet.Buffer) error {
	raw_pkt.ReadI(&p.Type)
	raw_pkt.ReadI(&p.Code)
	raw_pkt.ReadI(&p.Checksum)
	raw_pkt.ReadI(&p.Id)
	raw_pkt.ReadI(&p.Seq)

	/* TODO: data */

	return nil
}

func (p *Packet) Payload() packet.Packet {
	return nil
}

func (p *Packet) PayloadType() packet.Type {
	return packet.None
}

func (p *Packet) SetPayload(pl packet.Packet) error {
	return nil
}

func (p *Packet) InitChecksum(csum uint32) {
}

func (p *Packet) String() string {
	return packet.Stringify(p)
}

func (t Type) String() string {
	switch t {
	case EchoReply:         return "echo-reply"
	case DstUnreachable:    return "dst-unreach"
	case SrcQuench:         return "src-quench"
	case RedirectMsg:       return "redirect"
	case EchoRequest:       return "echo-request"
	case RouterAdv:         return "router-adv"
	case RouterSol:         return "router-sol"
	case TimeExceeded:      return "time-exceeded"
	case ParamProblem:      return "param-problem"
	case Timestamp:         return "timestamp-request"
	case TimestampReply:    return "timestamp-reply"
	case InfoRequest:       return "info-request"
	case InfoReply:         return "info-reply"
	case AddrMaskRequest:   return "addr-mask-request"
	case AddrMaskReply:     return "addr-mask-reply"
	default:                return "unknown"
	}
}

func (c Code) String() string {
	if c != 0 {
		return fmt.Sprintf("%x", uint8(c))
	}

	return ""
}
