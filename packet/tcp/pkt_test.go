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

package tcp

import "bytes"
import "net"
import "testing"

import "github.com/ghedo/hype/packet"
import "github.com/ghedo/hype/packet/ipv4"

var test_simple = []byte{
	0x00, 0x14, 0x00, 0x50, 0x00, 0x00, 0x15, 0x18, 0x00, 0x00, 0x01, 0xb0,
	0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x28,
}

func MakeTestSimple() *Packet {
	return &Packet{
		SrcPort: 20,
		DstPort: 80,
		Seq: 5400,
		Ack: 432,
		DataOff: 5,
		Flags: Syn,
		WindowSize: 8192,
		Urgent: 40,
	}
}

func Compare(t *testing.T, a, b *Packet) {
	if a.SrcPort != b.SrcPort {
		t.Fatalf("SrcPort mismatch: %d", b.SrcPort)
	}

	if a.DstPort != b.DstPort {
		t.Fatalf("DstPort mismatch: %d", b.DstPort)
	}

	if a.Seq != b.Seq {
		t.Fatalf("Seq mismatch: %d", b.Seq)
	}

	if a.Ack != b.Ack {
		t.Fatalf("Ack mismatch: %d", b.Ack)
	}

	if a.DataOff != b.DataOff {
		t.Fatalf("DataOff mismatch: %d", b.DataOff)
	}

	if a.Flags != b.Flags {
		t.Fatalf("Flags mismatch: %s", b.Flags)
	}

	if a.WindowSize != b.WindowSize {
		t.Fatalf("WindowSize mismatch: %d", b.WindowSize)
	}

	if a.Urgent != b.Urgent {
		t.Fatalf("Urgent mismatch: %d", b.Urgent)
	}

	if a.Checksum != b.Checksum {
		t.Fatalf("Checksum mismatch: %x", b.Checksum)
	}
}

func TestPack(t *testing.T) {
	var b packet.Buffer

	p := MakeTestSimple()

	err := p.Pack(&b)
	if err != nil {
		t.Fatalf("Error packing: %s", err)
	}

	if !bytes.Equal(test_simple, b.Bytes()) {
		t.Fatalf("Raw packet mismatch: %x", b.Bytes())
	}
}

func BenchmarkPack(bn *testing.B) {
	var b packet.Buffer

	p := MakeTestSimple()

	for n := 0; n < bn.N; n++ {
		p.Pack(&b)
	}
}

func TestUnpack(t *testing.T) {
	var p Packet

	cmp := MakeTestSimple()

	var b packet.Buffer
	b.Init(test_simple)

	err := p.Unpack(&b)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}

	Compare(t, cmp, &p)
}

func BenchmarkUnpack(bn *testing.B) {
	var p Packet

	var b packet.Buffer
	b.Init(test_simple)

	for n := 0; n < bn.N; n++ {
		p.Unpack(&b)
	}
}

var test_with_ipv4 = []byte{
	0x00, 0x14, 0x00, 0x50, 0x00, 0x00, 0x15, 0x18, 0x00, 0x00, 0x01, 0xb0,
	0x50, 0x02, 0x20, 0x00, 0xa6, 0x4f, 0x00, 0x28,
}

var ipsrc_str = "192.168.1.135"
var ipdst_str = "8.8.8.8"

func TestPackWithIPv4(t *testing.T) {
	var b packet.Buffer

	ip4 := ipv4.Make()
	ip4.SrcAddr = net.ParseIP(ipsrc_str)
	ip4.DstAddr = net.ParseIP(ipdst_str)

	tcp := MakeTestSimple()

	ip4.SetPayload(tcp)

	err := tcp.Pack(&b)
	if err != nil {
		t.Fatalf("Error packing: %s", err)
	}

	if !bytes.Equal(test_with_ipv4, b.Bytes()) {
		t.Fatalf("Raw packet mismatch: %x", b.Bytes())
	}
}

func TestUnpackWithIPv4(t *testing.T) {
	var p Packet

	cmp := MakeTestSimple()
	cmp.Checksum = 0xa64f

	var b packet.Buffer
	b.Init(test_with_ipv4)

	err := p.Unpack(&b)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}

	Compare(t, cmp, &p)
}
