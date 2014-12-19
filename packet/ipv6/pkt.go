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

// Provides encoding and decoding for IPv6 packets.
package ipv6

import "encoding/binary"
import "net"

import "github.com/ghedo/hype/packet"
import "github.com/ghedo/hype/packet/ipv4"

type Packet struct {
	Version     uint8
	Class       uint8
	Label       uint32
	Length      uint16        `name:"len"`
	NextHdr     ipv4.Protocol `name:"next"`
	HopLimit    uint8         `name:"hop"`
	SrcAddr     net.IP        `name:"src"`
	DstAddr     net.IP        `name:"dst"`
	pkt_payload packet.Packet `name:"skip"`
}

type Flags uint8

func Make() *Packet {
	return &Packet{
		Version: 6,
		HopLimit: 64,
	}
}

func (p *Packet) GetType() packet.Type {
	return packet.IPv6
}

func (p *Packet) GetLength() uint16 {
	return 40 + p.Length
}

func (p *Packet) Pack(raw_pkt *packet.Buffer) error {
	raw_pkt.WriteI(uint8(p.Version << 4 | (p.Class >> 4)))
	raw_pkt.WriteI(p.Class << 4 | uint8(p.Label >> 16))
	raw_pkt.WriteI(uint16(p.Label))

	raw_pkt.WriteI(p.Length)
	raw_pkt.WriteI(p.NextHdr)
	raw_pkt.WriteI(p.HopLimit)

	raw_pkt.Write(p.SrcAddr.To16())
	raw_pkt.Write(p.DstAddr.To16())

	return nil
}

func (p *Packet) pseudo_checksum() uint32 {
	var csum uint32

	for i := 0; i < 16; i += 2 {
		csum += uint32(p.SrcAddr.To16()[i]) << 8
		csum += uint32(p.SrcAddr.To16()[i + 1])
		csum += uint32(p.DstAddr.To16()[i]) << 8
		csum += uint32(p.DstAddr.To16()[i + 1])
	}

	csum += uint32(p.Length)
	csum += uint32(p.NextHdr)

	return csum
}

func (p *Packet) Unpack(raw_pkt *packet.Buffer) error {
	var versclass uint8
	raw_pkt.ReadI(&versclass)

	p.Version = versclass >> 4

	p.Class =
	 uint8((binary.BigEndian.Uint16(raw_pkt.BytesOff()[0:2]) >> 4) & 0x00FF)

	p.Label =
	 binary.BigEndian.Uint32(raw_pkt.BytesOff()[0:4]) & 0x000FFFFF

	raw_pkt.Next(3)

	raw_pkt.ReadI(&p.Length)
	raw_pkt.ReadI(&p.NextHdr)
	raw_pkt.ReadI(&p.HopLimit)

	p.SrcAddr = net.IP(raw_pkt.Next(16))
	p.DstAddr = net.IP(raw_pkt.Next(16))

	/* TODO: Options */

	return nil
}

func (p *Packet) Payload() packet.Packet {
	return p.pkt_payload
}

func (p *Packet) PayloadType() packet.Type {
	return ipv4.ProtocolToType(p.NextHdr)
}

func (p *Packet) SetPayload(pl packet.Packet) error {
	p.pkt_payload = pl
	p.NextHdr     = ipv4.TypeToProtocol(pl.GetType())
	p.Length      = pl.GetLength()

	pl.InitChecksum(p.pseudo_checksum())

	return nil
}

func (p *Packet) InitChecksum(csum uint32) {
}

func (p *Packet) String() string {
	return packet.Stringify(p)
}
