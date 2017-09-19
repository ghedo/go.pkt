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

// Provides an API for compiling and manipulating BPF filters. A filter can be
// either compiled from tcpdump-like expressions, or created from basic BPF
// instructions. Filters can then be either applied to packet sources (see the
// capture package) or directly run against binary data.
package filter

// #include <stdlib.h>
// #include "bpf_filter.h"
import "C"

import "fmt"
import "strings"
import "syscall"
import "unsafe"

type Filter struct {
    program C.struct_bpf_program
}

type Code uint16

const (
    LD Code = syscall.BPF_LD
    LDX     = syscall.BPF_LDX
    ST      = syscall.BPF_ST
    STX     = syscall.BPF_STX
    ALU     = syscall.BPF_ALU
    JMP     = syscall.BPF_JMP
    RET     = syscall.BPF_RET
    MISC    = syscall.BPF_MISC
)

type Size uint16

const (
    Word Size = syscall.BPF_W
    Half      = syscall.BPF_H
    Byte      = syscall.BPF_B
)

type Mode uint16

const (
    IMM Mode = syscall.BPF_IMM
    ABS      = syscall.BPF_ABS
    IND      = syscall.BPF_IND
    MEM      = syscall.BPF_MEM
    LEN      = syscall.BPF_LEN
    MSH      = syscall.BPF_MSH
)

type Src uint16

const (
    Const Src = syscall.BPF_K
    Index     = syscall.BPF_X
    Acc       = syscall.BPF_A
)

// Try to match the given buffer against the filter.
func (f *Filter) Match(buf []byte) bool {
    cbuf := (*C.char)(unsafe.Pointer(&buf[0]))
    blen := C.uint(len(buf))

    if C.bpf_filter(f.program.bf_insns, cbuf, blen, blen) > 0 {
        return true
    }

    return false
}

// Run filter on the given buffer and return its result.
func (f *Filter) Filter(buf []byte) uint {
    cbuf := (*C.char)(unsafe.Pointer(&buf[0]))
    blen := C.uint(len(buf))

    rc := C.bpf_filter(f.program.bf_insns, cbuf, blen, blen)
    return uint(rc)
}

// Validate the filter. The constraints are that each jump be forward and to a
// valid code. The code must terminate with either an accept or reject.
func (f *Filter) Validate() bool {
    if C.bpf_validate(f.program.bf_insns, C.int(f.program.bf_len)) > 0 {
        return true
    }

    return false
}

// Deallocate the filter.
func (f *Filter) Cleanup() {
    f.program.bf_len = 0

    if f.program.bf_insns != nil {
        C.free(unsafe.Pointer(f.program.bf_insns))
        f.program.bf_insns = nil
    }
}

// Return the number of instructions in the filter.
func (f *Filter) Len() int {
    prog := (*C.struct_bpf_program)(f.Program())
    flen := C.bpf_get_len(prog)
    return int(flen)
}

// Return the compiled BPF program.
func (f *Filter) Program() unsafe.Pointer {
    return unsafe.Pointer(&f.program)
}

func (f *Filter) String() string {
    var insns []string

    prog := (*C.struct_bpf_program)(f.Program())
    flen := C.bpf_get_len(prog)

    for i := C.int(0); i < flen; i++ {
        insn := C.bpf_get_insn(prog, i)

        str := fmt.Sprintf(
            "{ 0x%.2x, %3d, %3d, 0x%.8x },",
            insn.code, insn.jt, insn.jf, insn.k,
        )

        insns = append(insns, str)
    }

    return strings.Join(insns, "\n")
}

func (f *Filter) append_insn(code Code, jt, jf uint8, k uint32) {
    prog := (*C.struct_bpf_program)(f.Program())
    C.bpf_append_insn(
        prog, C.ushort(code), C.uchar(jt), C.uchar(jf), C.uint(k),
    )
}
