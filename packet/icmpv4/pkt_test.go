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

package icmpv4_test

import "bytes"
import "testing"

import "github.com/ghedo/go.pkt/packet"
import "github.com/ghedo/go.pkt/packet/icmpv4"

var test_simple = []byte{
    0x08, 0x00, 0xf7, 0xd2, 0x00, 0x0f, 0x00, 0x1e,
}

func MakeTestSimple() *icmpv4.Packet {
    return &icmpv4.Packet{
        Type: icmpv4.EchoRequest,
        Code: 0,
        Id: 15,
        Seq: 30,
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
    var p icmpv4.Packet

    cmp := MakeTestSimple()
    cmp.Checksum = 0xf7d2

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
    var p icmpv4.Packet
    var b packet.Buffer

    for n := 0; n < bn.N; n++ {
        b.Init(test_simple)
        p.Unpack(&b)
    }
}
