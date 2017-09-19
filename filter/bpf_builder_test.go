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

package filter_test

import "log"
import "testing"

import "github.com/ghedo/go.pkt/filter"

func TestEmpty(t *testing.T) {
    bld := filter.NewBuilder()

    flt := bld.Build()
    if flt.Len() != 0 {
        t.Fatalf("Len mismatch: %d", flt.Len())
    }
    flt.Cleanup()
}

var test_arp = `{ 0x28,   0,   0, 0x0000000c },
{ 0x15,   0,   1, 0x00000806 },
{ 0x06,   0,   0, 0x00040000 },
{ 0x06,   0,   0, 0x00000000 },`

func TestARP(t *testing.T) {
    arp := filter.NewBuilder().
        LD(filter.Half, filter.ABS, 12).
        JEQ(filter.Const, "", "fail", 0x806).
        RET(filter.Const, 0x40000).
        Label("fail").
        RET(filter.Const, 0x0).
        Build()

    if arp.String() != test_arp {
        t.Fatalf("Program mismatch: %s", arp.String())
    }
}

var test_dns = `{ 0x00,   0,   0, 0x00000014 },
{ 0xb1,   0,   0, 0x00000000 },
{ 0x0c,   0,   0, 0x00000000 },
{ 0x07,   0,   0, 0x00000000 },
{ 0x40,   0,   0, 0x00000000 },
{ 0x15,   0,   7, 0x07657861 },
{ 0x40,   0,   0, 0x00000004 },
{ 0x15,   0,   5, 0x6d706c65 },
{ 0x40,   0,   0, 0x00000008 },
{ 0x15,   0,   3, 0x03636f6d },
{ 0x50,   0,   0, 0x0000000c },
{ 0x15,   0,   1, 0x00000000 },
{ 0x06,   0,   0, 0x00000001 },
{ 0x06,   0,   0, 0x00000000 },`

func TestDNS(t *testing.T) {
    dns := filter.NewBuilder().
        LD(filter.Word, filter.IMM, 20).
        LDX(filter.Byte, filter.MSH, 0).
        ADD(filter.Index, 0).
        TAX().
        Label("lb_0").
        LD(filter.Word, filter.IND, 0).
        JEQ(filter.Const, "", "lb_1", 0x07657861).
        LD(filter.Word, filter.IND, 4).
        JEQ(filter.Const, "", "lb_1", 0x6d706c65).
        LD(filter.Word, filter.IND, 8).
        JEQ(filter.Const, "", "lb_1", 0x03636f6d).
        LD(filter.Byte, filter.IND, 12).
        JEQ(filter.Const, "", "lb_1", 0x00).
        RET(filter.Const, 1).
        Label("lb_1").
        RET(filter.Const, 0).
        Build()


    if dns.String() != test_dns {
        t.Fatalf("Program mismatch: %s", dns.String())
    }
}

func ExampleBuilder() {
    // Build a filter to match ARP packets on top of Ethernet
    flt := filter.NewBuilder().
        LD(filter.Half, filter.ABS, 12).
        JEQ(filter.Const, "", "fail", 0x806).
        RET(filter.Const, 0x40000).
        Label("fail").
        RET(filter.Const, 0x0).
        Build()

    if flt.Match([]byte("random data")) {
        log.Println("MATCH!!!")
    }
}
