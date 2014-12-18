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

// Provides an API for compiling and manipulating BPF filters.
package filter

// #include <stdlib.h>
// #include "bpf_filter.h"
import "C"

import "fmt"
import "strings"
import "unsafe"

type Filter struct {
	program C.struct_bpf_program
}

type Code uint16

const (
	LD Code = 0x00
	LDX     = 0x01
	ST      = 0x02
	STX     = 0x03
	ALU     = 0x04
	JMP     = 0x05
	RET     = 0x06
	MISC    = 0x07
)

type Size uint16

const (
	Word Size = 0x00
	Half      = 0x08
	Byte      = 0x10
)

type Mode uint16

const (
	IMM Mode = 0x00
	ABS      = 0x20
	IND      = 0x40
	MEM      = 0x60
	LEN      = 0x80
	MSH      = 0xa0
)

type Src uint16

const (
	Const Src = 0x00
	Index     = 0x08
	Acc       = 0x10
)

// Try to match the given buffer against the filter.
func (f *Filter) Match(raw_pkt []byte) bool {
	buf  := (*C.char)(unsafe.Pointer(&raw_pkt[0]))
	blen := C.uint(len(raw_pkt))

	if C.bpf_filter(f.program.bf_insns, buf, blen, blen) > 0 {
		return true
	}

	return false
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
