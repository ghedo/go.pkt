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

package arp

import "bytes"
import "net"
import "testing"

import "github.com/ghedo/hype/packet"

var test_simple = []byte{
	0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x4C, 0x72, 0xB9, 0x54,
	0xE5, 0x3D, 0xC0, 0xA8, 0x01, 0x87, 0x1F, 0x92, 0x2B, 0x56, 0xED, 0x77,
	0x1C, 0x3C, 0x09, 0xBF,
}

var hwsrc_str = "4c:72:b9:54:e5:3d"
var hwdst_str = "1f:92:2b:56:ed:77"
var ipsrc_str = "192.168.1.135"
var ipdst_str = "28.60.9.191"

func MakeTestSimple() *Packet {
	hwsrc, _ := net.ParseMAC(hwsrc_str)
	hwdst, _ := net.ParseMAC(hwdst_str)
	ipsrc := net.ParseIP(ipsrc_str)
	ipdst := net.ParseIP(ipdst_str)

	return &Packet{
		Operation: Request,

		HWType: 1,
		HWAddrLen: 6,
		HWSrcAddr: hwsrc,
		HWDstAddr: hwdst,

		ProtoType: packet.IPv4,
		ProtoAddrLen: 4,
		ProtoSrcAddr: ipsrc,
		ProtoDstAddr: ipdst,
	}
}

func Compare(t *testing.T, a, b *Packet) {
	if a.Operation != b.Operation {
		t.Fatalf("Operation mismatch: %d", b.Operation)
	}

	if a.HWType != b.HWType {
		t.Fatalf("HWType mismatch: %x", b.HWType)
	}

	if a.ProtoType != b.ProtoType {
		t.Fatalf("ProtoType mismatch: %x", b.ProtoType)
	}

	if a.HWAddrLen != 6 {
		t.Fatalf("HWAddrLen mismatch: %d", b.HWAddrLen)
	}

	if a.ProtoAddrLen != 4 {
		t.Fatalf("ProtoAddrLen mismatch: %d", b.ProtoAddrLen)
	}

	if a.HWAddrLen != b.HWAddrLen {
		t.Fatalf("HWAddrLen mismatch: %s", b.HWAddrLen)
	}

	if !bytes.Equal(a.HWSrcAddr, b.HWSrcAddr) {
		t.Fatalf("HWSrcAddr mismatch: %s", b.HWSrcAddr)
	}

	if !bytes.Equal(a.HWDstAddr, b.HWDstAddr) {
		t.Fatalf("HWDstAddr mismatch: %s", b.HWDstAddr)
	}

	if a.ProtoAddrLen != b.ProtoAddrLen {
		t.Fatalf("ProtoAddrLen mismatch: %s", b.ProtoAddrLen)
	}

	if !a.ProtoSrcAddr.Equal(b.ProtoSrcAddr) {
		t.Fatalf("ProtoSrcAddr mismatch: %s", b.ProtoSrcAddr)
	}

	if !a.ProtoDstAddr.Equal(b.ProtoDstAddr) {
		t.Fatalf("ProtoDstAddr mismatch: %s", b.ProtoDstAddr)
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
