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

type Filter C.struct_bpf_program

type Code uint16

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
)

// Try to match the given buffer against the filter.
func (f *Filter) Match(raw_pkt []byte) bool {
	buf  := (*C.char)(unsafe.Pointer(&raw_pkt[0]))
	blen := C.uint(len(raw_pkt))

	if C.bpf_filter(f.bf_insns, buf, blen, blen) > 0 {
		return true
	}

	return false
}

// Validate the filter. The constraints are that each jump be forward and to a
// valid code. The code must terminate with either an accept or reject.
func (f *Filter) Validate() bool {
	if C.bpf_validate(f.bf_insns, C.int(f.bf_len)) > 0 {
		return true
	}

	return false
}

// Deallocate the filter.
func (f *Filter) Cleanup() {
	f.bf_len = 0

	if f.bf_insns != nil {
		C.free(unsafe.Pointer(f.bf_insns))
		f.bf_insns = nil
	}
}

// Append a LD (load) instruction to the filter.
func (f *Filter) LD(s Size, m Mode, val uint32) {
	prog := (*C.struct_bpf_program)(unsafe.Pointer(f))
	code := Code(uint16(s) | uint16(m) | uint16(0x00))
	C.bpf_append_insn(prog, C.ushort(code), 0, 0, C.uint(val))
}

// Append a LDX (load index) instruction to the filter.
func (f *Filter) LDX(s Size, m Mode, val uint32) {
	prog := (*C.struct_bpf_program)(unsafe.Pointer(f))
	code := Code(uint16(s) | uint16(m) | uint16(0x01))
	C.bpf_append_insn(prog, C.ushort(code), 0, 0, C.uint(val))
}

// Append a ST (store) instruction to the filter.
func (f *Filter) ST(val uint32) {
	prog := (*C.struct_bpf_program)(unsafe.Pointer(f))
	code := Code(uint16(0x02))
	C.bpf_append_insn(prog, C.ushort(code), 0, 0, C.uint(val))
}

// Append a STX (store to index) instruction to the filter.
func (f *Filter) STX(val uint32) {
	prog := (*C.struct_bpf_program)(unsafe.Pointer(f))
	code := Code(uint16(0x03))
	C.bpf_append_insn(prog, C.ushort(code), 0, 0, C.uint(val))
}

// Append a JA (jump absolute) instruction to the filter.
func (f *Filter) JA(s Src, addr uint32) {
	prog := (*C.struct_bpf_program)(unsafe.Pointer(f))
	code := Code(uint16(s) | uint16(0x00) | uint16(0x05))
	C.bpf_append_insn(prog, C.ushort(code), 0, 0, C.uint(addr))
}

// Append a JEQ (jump if equal) instruction to the filter.
func (f *Filter) JEQ(s Src, jt, jf uint8, cmp uint32) {
	prog := (*C.struct_bpf_program)(unsafe.Pointer(f))
	code := Code(uint16(s) | uint16(0x10) | uint16(0x05))
	C.bpf_append_insn(prog, C.ushort(code), C.uchar(jt), C.uchar(jf), C.uint(cmp))
}

// Append a JGT (jump if greater than) instruction to the filter.
func (f *Filter) JGT(s Src, jt, jf uint8, cmp uint32) {
	prog := (*C.struct_bpf_program)(unsafe.Pointer(f))
	code := Code(uint16(s) | uint16(0x10) | uint16(0x05))
	C.bpf_append_insn(prog, C.ushort(code), C.uchar(jt), C.uchar(jf), C.uint(cmp))
}

// Append a JGE (jump if greater or equal) instruction to the filter.
func (f *Filter) JGE(s Src, jt, jf uint8, cmp uint32) {
	prog := (*C.struct_bpf_program)(unsafe.Pointer(f))
	code := Code(uint16(s) | uint16(0x10) | uint16(0x05))
	C.bpf_append_insn(prog, C.ushort(code), C.uchar(jt), C.uchar(jf), C.uint(cmp))
}

// Append a JSET instruction to the filter.
func (f *Filter) JSET(s Src, jt, jf uint8, cmp uint32) {
	prog := (*C.struct_bpf_program)(unsafe.Pointer(f))
	code := Code(uint16(s) | uint16(0x10) | uint16(0x05))
	C.bpf_append_insn(prog, C.ushort(code), C.uchar(jt), C.uchar(jf), C.uint(cmp))
}

// Append a RET (return) instruction to the filter.
func (f *Filter) RET(s Src, bytes uint32) {
	prog := (*C.struct_bpf_program)(unsafe.Pointer(f))
	code := Code(uint16(s) | uint16(0x06))
	C.bpf_append_insn(prog, C.ushort(code), 0, 0, C.uint(bytes))
}

func (f *Filter) String() string {
	var insns []string

	prog := (*C.struct_bpf_program)(unsafe.Pointer(f))
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
