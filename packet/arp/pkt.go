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

// Provides encoding and decoding for ARP packets.
package arp

import "net"

import "github.com/ghedo/hype/packet"
import "github.com/ghedo/hype/packet/eth"

type Packet struct {
	Operation     Operation        `name:"op"`

	HWType        uint16
	HWAddrLen     uint8            `name:"hwlen"`
	HWSrcAddr     net.HardwareAddr `name:"hwsrc"`
	HWDstAddr     net.HardwareAddr `name:"hwdst"`

	ProtoType     eth.EtherType    `name:"ptype"`
	ProtoAddrLen  uint8            `name:"plen"`
	ProtoSrcAddr  net.IP           `name:"psrc"`
	ProtoDstAddr  net.IP           `name:"pdst"`
}

type Operation uint16

const (
	Request Operation = 1
	Reply             = 2
)

func Make() *Packet {
	return &Packet {
		Operation: Request,

		HWType: 1,
		HWAddrLen: 6,

		ProtoType: eth.IPv4,
		ProtoAddrLen: 4,
	}
}

func (p *Packet) GetType() packet.Type {
	return packet.ARP
}

func (p *Packet) GetLength() uint16 {
	return 8 + uint16(p.HWAddrLen) * 2 + uint16(p.ProtoAddrLen) * 2
}

func (p *Packet) Pack(raw_pkt *packet.Buffer) error {
	raw_pkt.WriteI(p.HWType)
	raw_pkt.WriteI(p.ProtoType)

	raw_pkt.WriteI(p.HWAddrLen)
	raw_pkt.WriteI(p.ProtoAddrLen)

	raw_pkt.WriteI(p.Operation)

	raw_pkt.Write(p.HWSrcAddr[len(p.HWSrcAddr) - int(p.HWAddrLen):])
	raw_pkt.Write(p.ProtoSrcAddr[len(p.ProtoSrcAddr) - int(p.ProtoAddrLen):])

	raw_pkt.Write(p.HWDstAddr[len(p.HWDstAddr) - int(p.HWAddrLen):])
	raw_pkt.Write(p.ProtoDstAddr[len(p.ProtoDstAddr) - int(p.ProtoAddrLen):])

	return nil
}

func (p *Packet) Unpack(raw_pkt *packet.Buffer) error {
	raw_pkt.ReadI(&p.HWType)
	raw_pkt.ReadI(&p.ProtoType)

	raw_pkt.ReadI(&p.HWAddrLen)
	raw_pkt.ReadI(&p.ProtoAddrLen)

	raw_pkt.ReadI(&p.Operation)

	p.HWSrcAddr = net.HardwareAddr(raw_pkt.Next(int(p.HWAddrLen)))
	p.ProtoSrcAddr = net.IP(raw_pkt.Next(int(p.ProtoAddrLen)))

	p.HWDstAddr = net.HardwareAddr(raw_pkt.Next(int(p.HWAddrLen)))
	p.ProtoDstAddr = net.IP(raw_pkt.Next(int(p.ProtoAddrLen)))

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

func (o Operation) String() string {
	switch o {
	case Request:
		return "request"

	case Reply:
		return "reply"

	default:
		return "invalid"
	}
}
