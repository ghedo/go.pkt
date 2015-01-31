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

package icmpv6_test

import "bytes"
import "net"
import "testing"

import "github.com/ghedo/go.pkt/packet"
import "github.com/ghedo/go.pkt/packet/icmpv6"
import "github.com/ghedo/go.pkt/packet/ipv6"

var test_simple = []byte{
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func MakeTestSimple() *icmpv6.Packet {
	return &icmpv6.Packet{
		Type: icmpv6.EchoRequest,
	}
}

func TestPack(t *testing.T) {
	var b packet.Buffer
	b.Init(make([]byte, len(test_simple)))

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
	b.Init(make([]byte, len(test_simple)))

	p := MakeTestSimple()

	for n := 0; n < bn.N; n++ {
		p.Pack(&b)
	}
}

func TestUnpack(t *testing.T) {
	var p icmpv6.Packet

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
	var p icmpv6.Packet
	var b packet.Buffer

	for n := 0; n < bn.N; n++ {
		b.Init(test_simple)
		p.Unpack(&b)
	}
}

var test_with_ipv6 = []byte{
	0x80, 0x00, 0x5b, 0xed, 0x00, 0x00, 0x00, 0x00,
}

var ipsrc_str = "fe80::4e72:b9ff:fe54:e53d"
var ipdst_str = "2001:4860:4860::8888"

func TestPackWithIPv6(t *testing.T) {
	var b packet.Buffer
	b.Init(make([]byte, len(test_with_ipv6)))

	ip6 := ipv6.Make()
	ip6.SrcAddr = net.ParseIP(ipsrc_str)
	ip6.DstAddr = net.ParseIP(ipdst_str)

	icmp6 := MakeTestSimple()

	ip6.SetPayload(icmp6)

	err := icmp6.Pack(&b)
	if err != nil {
		t.Fatalf("Error packing: %s", err)
	}

	if !bytes.Equal(test_with_ipv6, b.Buffer()) {
		t.Fatalf("Raw packet mismatch: %x", b.Buffer())
	}
}

func TestUnpackWithIPv6(t *testing.T) {
	var p icmpv6.Packet

	cmp := MakeTestSimple()
	cmp.Checksum = 0x5bed

	var b packet.Buffer
	b.Init(test_with_ipv6)

	err := p.Unpack(&b)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}

	if !p.Equals(cmp) {
		t.Fatalf("Packet mismatch:\n%s\n%s", &p, cmp)
	}
}
