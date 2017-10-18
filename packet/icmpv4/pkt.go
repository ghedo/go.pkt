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

import "github.com/ghedo/go.pkt/packet"
import "github.com/ghedo/go.pkt/packet/ipv4"

type Packet struct {
    Type        Type
    Code        Code
    Checksum    uint16        `string:"sum"`
    Id          uint16
    Seq         uint16
    pkt_payload packet.Packet `cmp:"skip" string:"skip"`
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
    return &Packet{
        Type: EchoRequest,
    }
}

func (p *Packet) GetType() packet.Type {
    return packet.ICMPv4
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
    if other == nil || other.GetType() != packet.ICMPv4 {
        return false
    }

    if (other.(*Packet).Type == EchoRequest && p.Type == EchoReply) ||
       (other.(*Packet).Type == Timestamp && p.Type == TimestampReply) ||
       (other.(*Packet).Type == InfoRequest && p.Type == InfoReply) ||
       (other.(*Packet).Type == AddrMaskRequest && p.Type == AddrMaskReply) {
        return (other.(*Packet).Seq == p.Seq) &&
               (other.(*Packet).Id == p.Id)
    }

    return false
}

func (p *Packet) Pack(buf *packet.Buffer) error {
    buf.WriteN(byte(p.Type))
    buf.WriteN(byte(p.Code))
    buf.WriteN(uint16(0x0000))
    buf.WriteN(p.Id)
    buf.WriteN(p.Seq)

    p.Checksum = ipv4.CalculateChecksum(buf.LayerBytes(), 0)
    buf.PutUint16N(2, p.Checksum)

    return nil
}

func (p *Packet) Unpack(buf *packet.Buffer) error {
    buf.ReadN(&p.Type)
    buf.ReadN(&p.Code)
    buf.ReadN(&p.Checksum)
    buf.ReadN(&p.Id)
    buf.ReadN(&p.Seq)

    /* TODO: data */

    return nil
}

func (p *Packet) Payload() packet.Packet {
    return p.pkt_payload
}

func (p *Packet) GuessPayloadType() packet.Type {
    switch p.Type {
    case DstUnreachable, SrcQuench, RedirectMsg, TimeExceeded, ParamProblem:
        return packet.IPv4
    }

    return packet.None
}

func (p *Packet) SetPayload(pl packet.Packet) error {
    switch p.Type {
    case DstUnreachable, SrcQuench, RedirectMsg, TimeExceeded, ParamProblem:
        p.pkt_payload = pl
    }

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
