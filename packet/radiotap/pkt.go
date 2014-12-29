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

// Provides encoding and decoding for RadioTap packets.
package radiotap

import "fmt"

import "github.com/ghedo/hype/packet"

type Packet struct {
	Version         uint8
	Length          uint16
	Present         Present
	Data            []byte        `cmp:"skip" string:"skip"`
	pkt_payload     packet.Packet `cmp:"skip" string:"skip"`
}

type Present uint32

const (
	TSFT Present = 1 << iota
	Flags
	Rate
	Channel
	FHSS
	DbmAntSignal
	DbmAntNoise
	LockQuality
	TXAttenuation
	DbTXAttenuation
	DbmTXPower
	Antenna
	DbAntSignal
	DbAntNoise
	EXT
)

func Make() *Packet {
	return &Packet{
	}
}

func (p *Packet) GetType() packet.Type {
	return packet.RadioTap
}

func (p *Packet) GetLength() uint16 {
	if p.pkt_payload != nil {
		return p.pkt_payload.GetLength() + 8 + uint16(len(p.Data))
	}

	return 8 + uint16(len(p.Data))
}

func (p *Packet) Equals(other packet.Packet) bool {
	return packet.Compare(p, other)
}

func (p *Packet) Answers(other packet.Packet) bool {
	return false
}

func (p *Packet) Pack(buf *packet.Buffer) error {
	buf.WriteL(p.Version)
	buf.WriteL(uint8(0x00))
	buf.WriteL(p.Length)
	buf.WriteL(p.Present)

	/* TODO: actually decode fields */
	buf.Write(p.Data)

	return nil
}

func (p *Packet) Unpack(buf *packet.Buffer) error {
	buf.ReadN(&p.Version)

	var pad uint8
	buf.ReadL(&pad)

	buf.ReadL(&p.Length)
	buf.ReadL(&p.Present)

	/* TODO: actually decode fields */
	p.Data = buf.Next(int(p.Length) - 8)

	return nil
}

func (p *Packet) Payload() packet.Packet {
	return p.pkt_payload
}

func (p *Packet) GuessPayloadType() packet.Type {
	return packet.WiFi
}

func (p *Packet) SetPayload(pl packet.Packet) error {
	p.pkt_payload = pl
	p.Length      = p.GetLength()

	return nil
}

func (p *Packet) InitChecksum(csum uint32) {
}

func (p *Packet) String() string {
	return packet.Stringify(p)
}

func (p Present) String() string {
	return fmt.Sprintf("0x%x", uint32(p))
}
