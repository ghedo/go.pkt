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

package udp_test

import "bytes"
import "net"
import "testing"

import "github.com/ghedo/hype/packet"
import "github.com/ghedo/hype/packet/ipv4"
import "github.com/ghedo/hype/packet/udp"

var test_simple = []byte{
	0xcb, 0xa6, 0x00, 0x50, 0x00, 0x12, 0x00, 0x00,
}

func MakeTestSimple() *udp.Packet {
	return &udp.Packet{
		SrcPort: 52134,
		DstPort: 80,
		Length: 18,
	}
}

func TestPack(t *testing.T) {
	var b packet.Buffer

	p := MakeTestSimple()

	err := p.Pack(&b)
	if err != nil {
		t.Fatalf("Error packing: %s", err)
	}

	if !bytes.Equal(test_simple, b.Buffer()) {
		t.Fatalf("Raw packet mismatch: %x", b.Buffer())
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
	var p udp.Packet

	cmp := MakeTestSimple()

	var b packet.Buffer
	b.Init(test_simple)

	err := p.Unpack(&b)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}

	if !p.Equals(cmp) {
		t.Fatalf("Packet mismatch:\n%s\n%s", &p, cmp)
	}
}

func BenchmarkUnpack(bn *testing.B) {
	var p udp.Packet

	var b packet.Buffer
	b.Init(test_simple)

	for n := 0; n < bn.N; n++ {
		p.Unpack(&b)
	}
}

var test_with_ipv4 = []byte{
	0xcb, 0xa6, 0x00, 0x50, 0x00, 0x12, 0x61, 0x9e,
}

var ipsrc_str = "192.168.1.135"
var ipdst_str = "8.8.8.8"

func TestPackWithIPv4(t *testing.T) {
	var b packet.Buffer

	ip4 := ipv4.Make()
	ip4.SrcAddr = net.ParseIP(ipsrc_str)
	ip4.DstAddr = net.ParseIP(ipdst_str)

	udp := &udp.Packet{
		SrcPort: 52134,
		DstPort: 80,
		Length: 18,
	}

	ip4.SetPayload(udp)

	err := udp.Pack(&b)
	if err != nil {
		t.Fatalf("Error packing: %s", err)
	}

	if !bytes.Equal(test_with_ipv4, b.Buffer()) {
		t.Fatalf("Raw packet mismatch: %x", b.Buffer())
	}
}

func TestUnpackWithIPv4(t *testing.T) {
	var p udp.Packet

	cmp := MakeTestSimple()
	cmp.Checksum = 0x619e

	var b packet.Buffer
	b.Init(test_with_ipv4)

	err := p.Unpack(&b)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}

	if !p.Equals(cmp) {
		t.Fatalf("Packet mismatch:\n%s\n%s", &p, cmp)
	}
}
