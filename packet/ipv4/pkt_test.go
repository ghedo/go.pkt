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

package ipv4_test

import "bytes"
import "net"
import "testing"

import "github.com/ghedo/hype/packet"
import "github.com/ghedo/hype/packet/ipv4"

var test_simple = []byte{
	0x45, 0x03, 0x00, 0x14, 0x00, 0x0f, 0x40, 0x00, 0x64, 0x06, 0x48, 0x97,
	0xc0, 0xa8, 0x01, 0x87, 0x08, 0x08, 0x04, 0x04,
}

var ipsrc_str = "192.168.1.135"
var ipdst_str = "8.8.4.4"

func MakeTestSimple() *ipv4.Packet {
	return &ipv4.Packet{
		Version: 4,
		IHL: 5,
		Length: 20,
		TOS: 3,
		Id: 15,
		TTL: 100,
		Flags: ipv4.DontFragment,
		Protocol: ipv4.TCP,
		SrcAddr: net.ParseIP(ipsrc_str),
		DstAddr: net.ParseIP(ipdst_str),
	}
}

func Compare(t *testing.T, a, b *ipv4.Packet) {
	if a.Version != b.Version {
		t.Fatalf("Version mismatch: %d", b.Version)
	}

	if a.IHL != b.IHL {
		t.Fatalf("IHL mismatch: %d", b.IHL)
	}

	if a.TOS != b.TOS {
		t.Fatalf("TOS mismatch: %d", b.TOS)
	}

	if a.Length != b.Length {
		t.Fatalf("Length mismatch: %d", b.Length)
	}

	if a.Id != b.Id {
		t.Fatalf("Id mismatch: %d", b.Id)
	}

	if a.Flags != b.Flags {
		t.Fatalf("Flags mismatch: %d", b.Flags)
	}

	if a.TTL != b.TTL {
		t.Fatalf("TTL mismatch: %d", b.TTL)
	}

	if a.Protocol != b.Protocol {
		t.Fatalf("Protocol mismatch: %d", b.Protocol)
	}

	if a.Checksum != b.Checksum {
		t.Fatalf("Checksum mismatch: %d", b.Checksum)
	}

	if !a.SrcAddr.Equal(b.SrcAddr) {
		t.Fatalf("ProtoSrcAddr mismatch: %s", b.SrcAddr)
	}

	if !a.DstAddr.Equal(b.DstAddr) {
		t.Fatalf("ProtoDstAddr mismatch: %s", b.DstAddr)
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
	var p ipv4.Packet

	cmp := MakeTestSimple()
	cmp.Checksum = 0x4897

	var b packet.Buffer
	b.Init(test_simple)

	err := p.Unpack(&b)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}

	Compare(t, cmp, &p)
}

func BenchmarkUnpack(bn *testing.B) {
	var p ipv4.Packet

	var b packet.Buffer
	b.Init(test_simple)

	for n := 0; n < bn.N; n++ {
		p.Unpack(&b)
	}
}
