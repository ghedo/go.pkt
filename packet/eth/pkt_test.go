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

package eth

import "bytes"
import "net"
import "testing"

import "github.com/ghedo/hype/packet"

var hwsrc_str = "4c:72:b9:54:e5:3d"
var hwdst_str = "1f:92:2b:56:ed:77"

var test_simple = []byte{
	0x1f, 0x92, 0x2b, 0x56, 0xed, 0x77, 0x4c, 0x72, 0xb9, 0x54, 0xe5, 0x3d,
	0x08, 0x00,
}

func Compare(t *testing.T, a, b *Packet) {
	if !bytes.Equal(a.SrcAddr, b.SrcAddr) {
		t.Fatalf("SrcAddr mismatch: %s",b.SrcAddr)
	}

	if !bytes.Equal(a.DstAddr, b.DstAddr) {
		t.Fatalf("DstAddr mismatch: %s", b.DstAddr)
	}

	if a.Type != b.Type {
		t.Fatalf("Type mismatch: %s", b.Type)
	}
}

func MakeTestSimple() *Packet {
	hwsrc, _ := net.ParseMAC(hwsrc_str)
	hwdst, _ := net.ParseMAC(hwdst_str)

	return &Packet{
		SrcAddr: hwsrc,
		DstAddr: hwdst,
		Type:    IPv4,
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
