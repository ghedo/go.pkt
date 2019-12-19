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

// Provides encoding and decoding for IPv4 packets.
package ipv4

import "fmt"
import "net"
import "strings"

import "github.com/ghedo/go.pkt/packet"

type Packet struct {
    Version     uint8
    IHL         uint8
    TOS         uint8         `cmp:"skip"`
    Length      uint16        `cmp:"skip"`
    Id          uint16
    Flags       Flags
    FragOff     uint16
    TTL         uint8         `cmp:"skip"`
    Protocol    Protocol      `string:"proto"`
    Checksum    uint16        `cmp:"skip" string:"sum"`
    SrcAddr     net.IP        `string:"src"`
    DstAddr     net.IP        `string:"dst"`
    pkt_payload packet.Packet `cmp:"skip" string:"skip"`
}

type Flags uint8

const (
    Evil     Flags = 1 << 2 /* RFC3514 */
    DontFragment   = 1 << 1
    MoreFragments  = 1 << 0
)

type Protocol uint8

const (
    None Protocol = 0x00
    GRE           = 0x2F
    ICMPv4        = 0x01
    ICMPv6        = 0x3A
    IGMP          = 0x02
    IPSecAH       = 0x33
    IPSecESP      = 0x32
    IPv6          = 0x29
    ISIS          = 0x7C
    L2TP          = 0x73
    OSPF          = 0x59
    SCTP          = 0x84
    TCP           = 0x06
    UDP           = 0x11
    UDPLite       = 0x88
)

func Make() *Packet {
    return &Packet{
        Version: 4,
        IHL: 5,
        Length: 20,
        TTL: 64,
        Id: 1,
    }
}

func (p *Packet) GetType() packet.Type {
    return packet.IPv4
}

func (p *Packet) GetLength() uint16 {
    if p.pkt_payload != nil {
        return p.pkt_payload.GetLength() + 20
    }

    return 20
}

func (p *Packet) Equals(other packet.Packet) bool {
    return packet.Compare(p, other)
}

func (p *Packet) Answers(other packet.Packet) bool {
    if other == nil || other.GetType() != packet.IPv4 {
        return false
    }

    if p.Payload() != nil &&
       p.Payload().GetType() == packet.ICMPv4 &&
       p.Payload().Payload() != nil {
        return p.Payload().Payload().Equals(other)
    }

    if !p.SrcAddr.Equal(other.(*Packet).DstAddr) ||
        p.Protocol != other.(*Packet).Protocol {
        return false
    }

    if p.Payload() != nil {
        return p.Payload().Answers(other.Payload())
    }

    return true
}

func (p *Packet) Pack(buf *packet.Buffer) error {
    buf.WriteN((p.Version << 4) | p.IHL)
    buf.WriteN(p.TOS)
    buf.WriteN(p.Length)
    buf.WriteN(p.Id)
    buf.WriteN((uint16(p.Flags) << 13) | p.FragOff)
    buf.WriteN(p.TTL)
    buf.WriteN(p.Protocol)
    buf.WriteN(uint16(0x00))
    buf.Write(p.SrcAddr.To4())
    buf.Write(p.DstAddr.To4())

    p.checksum(buf.LayerBytes()[:20])
    buf.PutUint16N(10, p.Checksum)

    return nil
}

func (p *Packet) checksum(raw_bytes []byte) {
    var csum uint32

    for i := 0; i < len(raw_bytes) - 1; i += 2 {
        csum += uint32(raw_bytes[i]) << 8
        csum += uint32(raw_bytes[i + 1])
    }

    p.Checksum = ^uint16((csum >> 16) + csum)
}

func (p *Packet) pseudo_checksum() uint32 {
    var csum uint32

    csum += (uint32(p.SrcAddr.To4()[0]) + uint32(p.SrcAddr.To4()[2])) << 8
    csum +=  uint32(p.SrcAddr.To4()[1]) + uint32(p.SrcAddr.To4()[3])
    csum += (uint32(p.DstAddr.To4()[0]) + uint32(p.DstAddr.To4()[2])) << 8
    csum +=  uint32(p.DstAddr.To4()[1]) + uint32(p.DstAddr.To4()[3])
    csum +=  uint32(p.Protocol)
    csum +=  uint32(p.pkt_payload.GetLength())

    return csum
}

func (p *Packet) Unpack(buf *packet.Buffer) error {
    var versihl uint8
    buf.ReadN(&versihl)

    p.Version  = versihl >> 4
    p.IHL      = versihl & 0x0F

    buf.ReadN(&p.TOS)
    buf.ReadN(&p.Length)
    buf.ReadN(&p.Id)

    var flagsfrag uint16
    buf.ReadN(&flagsfrag)
    p.Flags   = Flags(flagsfrag >> 13)
    p.FragOff = flagsfrag & 0x1FFF

    buf.ReadN(&p.TTL)

    buf.ReadN(&p.Protocol)

    buf.ReadN(&p.Checksum)

    p.SrcAddr = net.IP(buf.Next(4))
    p.DstAddr = net.IP(buf.Next(4))

    /* TODO: Options */

    return nil
}

func (p *Packet) Payload() packet.Packet {
    return p.pkt_payload
}

func (p *Packet) GuessPayloadType() packet.Type {
    return ProtocolToType(p.Protocol)
}

func (p *Packet) SetPayload(pl packet.Packet) error {
    p.pkt_payload = pl
    p.Protocol    = TypeToProtocol(pl.GetType())
    p.Length      = p.GetLength()

    pl.InitChecksum(p.pseudo_checksum())

    return nil
}

func (p *Packet) InitChecksum(csum uint32) {
}

func (p *Packet) String() string {
    return packet.Stringify(p)
}

func (f Flags) String() string {
    var flags []string

    if f & Evil != 0  {
        flags = append(flags, "evil")
    }

    if f & DontFragment != 0 {
        flags = append(flags, "dont-fragment")
    }

    if f & MoreFragments != 0 {
        flags = append(flags, "more-fragments")
    }

    return strings.Join(flags, "|")
}

func CalculateChecksum(raw_bytes []byte, csum uint32) uint16 {
    length := len(raw_bytes) - 1

    for i := 0; i < length; i += 2 {
        csum += uint32(raw_bytes[i]) << 8
        csum += uint32(raw_bytes[i + 1])
    }

	if len(raw_bytes)%2 == 1 {
		csum += uint32(raw_bytes[length]) << 8
	}

    csum = (csum >> 16) + (csum & 0xffff)

    return ^uint16(csum + (csum >> 16))
}

var ipv4proto_to_type_map = map[Protocol]packet.Type{
    None:     packet.None,
    GRE:      packet.GRE,
    ICMPv4:   packet.ICMPv4,
    ICMPv6:   packet.ICMPv6,
    IGMP:     packet.IGMP,
    IPSecAH:  packet.IPSec,
    IPSecESP: packet.IPSec,
    IPv6:     packet.IPv6,
    UDP:      packet.UDP,
    ISIS:     packet.ISIS,
    L2TP:     packet.L2TP,
    OSPF:     packet.OSPF,
    SCTP:     packet.SCTP,
    UDPLite:  packet.UDPLite,
    TCP:      packet.TCP,
}

// Create a new Type from the given IP protocol ID.
func ProtocolToType(proto Protocol) packet.Type {
    for p, t := range ipv4proto_to_type_map {
        if p == proto {
            return t
        }
    }

    return packet.Raw
}

// Convert the Type to the corresponding IP protocol ID.
func TypeToProtocol(pkttype packet.Type) Protocol {
    for p, t := range ipv4proto_to_type_map {
        if t == pkttype {
            return p
        }
    }

    return None
}

func (p Protocol) String() string {
    switch p {
    case GRE:      return "GRE"
    case ICMPv4:   return "ICMPv4"
    case ICMPv6:   return "ICMPv6"
    case IGMP:     return "IGMP"
    case IPSecAH:  return "IPSecAH"
    case IPSecESP: return "IPSecESP"
    case IPv6:     return "IPv6"
    case UDP:      return "UDP"
    case ISIS:     return "ISIS"
    case L2TP:     return "L2TP"
    case OSPF:     return "OSPF"
    case SCTP:     return "SCTP"
    case UDPLite:  return "UDPLite"
    case TCP:      return "TCP"
    default:       return fmt.Sprintf("0x%x", uint16(p))
    }
}
