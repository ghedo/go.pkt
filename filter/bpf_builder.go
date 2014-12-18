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

// #include "bpf_filter.h"
import "C"

// A Builder is used to compile a BPF filter from basic BPF instructions.
type Builder struct {
	filter    *Filter
	labels    map[string]int

	jumps_k  map[int]string
	jumps_jt map[int]string
	jumps_jf map[int]string
}

func NewBuilder() *Builder {
	b := &Builder{}

	b.filter   = &Filter{}
	b.labels   = make(map[string]int)
	b.jumps_k  = make(map[int]string)
	b.jumps_jt = make(map[int]string)
	b.jumps_jf = make(map[int]string)

	return b
}

func (b *Builder) Build() *Filter {
	prog := (*C.struct_bpf_program)(b.filter.Program())
	flen := int(C.bpf_get_len(prog))

	for i := 0; i < flen; i++ {
		insn := C.bpf_get_insn(prog, C.int(i))

		/* if lbl, ok := b.jumps_k[i]; ok { */
		/* 	addr := b.labels[lbl] */
		/* 	insn.k = C.bpf_u_int32(addr - i - 1) */
		/* } */

		if lbl, ok := b.jumps_jt[i]; ok {
			addr := b.labels[lbl]
			if addr != 0 {
				insn.jt = C.u_char(addr - i - 1)
			}
		}

		if lbl, ok := b.jumps_jf[i]; ok {
			addr := b.labels[lbl]
			if addr != 0  {
				insn.jf = C.u_char(addr - i - 1)
			}
		}
	}

	return b.filter
}

func (b *Builder) Label(name string) *Builder {
	b.labels[name] = b.filter.Len()
	return b
}

// Append a LD (load) instruction to the filter.
func (b *Builder) LD(s Size, m Mode, val uint32) *Builder {
	code := Code(uint16(s) | uint16(m)) | LD
	b.filter.append_insn(code, 0, 0, val)
	return b
}

// Append a LDX (load index) instruction to the filter.
func (b *Builder) LDX(s Size, m Mode, val uint32) *Builder {
	code := Code(uint16(s) | uint16(m) | LDX)
	b.filter.append_insn(code, 0, 0, val)
	return b
}

// Append a ST (store) instruction to the filter.
func (b *Builder) ST(val uint32) *Builder {
	b.filter.append_insn(ST, 0, 0, val)
	return b
}

// Append a STX (store to index) instruction to the filter.
func (b *Builder) STX(val uint32) *Builder {
	b.filter.append_insn(STX, 0, 0, val)
	return b
}

// Append a ADD instruction to the filter.
func (b *Builder) ADD(s Src, val uint32) *Builder {
	code := Code(uint16(s) | uint16(0x00) | ALU)
	b.filter.append_insn(code, 0, 0, val)
	return b
}

// Append a SUB instruction to the filter.
func (b *Builder) SUB(s Src, val uint32) *Builder {
	code := Code(uint16(s) | uint16(0x10) | ALU)
	b.filter.append_insn(code, 0, 0, val)
	return b
}

// Append a MUL instruction to the filter.
func (b *Builder) MUL(s Src, val uint32) *Builder {
	code := Code(uint16(s) | uint16(0x20) | ALU)
	b.filter.append_insn(code, 0, 0, val)
	return b
}

// Append a DIV instruction to the filter.
func (b *Builder) DIV(s Src, val uint32) *Builder {
	code := Code(uint16(s) | uint16(0x30) | ALU)
	b.filter.append_insn(code, 0, 0, val)
	return b
}

// Append a AND instruction to the filter.
func (b *Builder) AND(s Src, val uint32) *Builder {
	code := Code(uint16(s) | uint16(0x40) | ALU)
	b.filter.append_insn(code, 0, 0, val)
	return b
}

// Append a OR instruction to the filter.
func (b *Builder) OR(s Src, val uint32) *Builder {
	code := Code(uint16(s) | uint16(0x50) | ALU)
	b.filter.append_insn(code, 0, 0, val)
	return b
}

// Append a LSH instruction to the filter.
func (b *Builder) LSH(s Src, val uint32) *Builder {
	code := Code(uint16(s) | uint16(0x60) | ALU)
	b.filter.append_insn(code, 0, 0, val)
	return b
}

// Append a RSH instruction to the filter.
func (b *Builder) RSH(s Src, val uint32) *Builder {
	code := Code(uint16(s) | uint16(0x70) | ALU)
	b.filter.append_insn(code, 0, 0, val)
	return b
}

// Append a NEG instruction to the filter.
func (b *Builder) NEG() *Builder {
	code := Code(uint16(0x80) | ALU)
	b.filter.append_insn(code, 0, 0, 0)
	return b
}

// Append a JA (jump absolute) instruction to the filter.
func (b *Builder) JA(j string) *Builder {
	b.jumps_k[b.filter.Len()] = j

	code := Code(uint16(0x00) | JMP)
	b.filter.append_insn(code, 0, 0, 0)
	return b
}

// Append a JEQ (jump if equal) instruction to the filter.
func (b *Builder) JEQ(s Src, jt, jf string, cmp uint32) *Builder {
	b.jumps_jt[b.filter.Len()] = jt
	b.jumps_jf[b.filter.Len()] = jf

	code := Code(uint16(s) | uint16(0x10) | JMP)
	b.filter.append_insn(code, 0, 0, cmp)
	return b
}

// Append a JGT (jump if greater than) instruction to the filter.
func (b *Builder) JGT(s Src, jt, jf string, cmp uint32) *Builder {
	b.jumps_jt[b.filter.Len()] = jt
	b.jumps_jf[b.filter.Len()] = jf

	code := Code(uint16(s) | uint16(0x20) | JMP)
	b.filter.append_insn(code, 0, 0, cmp)
	return b
}

// Append a JGE (jump if greater or equal) instruction to the filter.
func (b *Builder) JGE(s Src, jt, jf string, cmp uint32) *Builder {
	b.jumps_jt[b.filter.Len()] = jt
	b.jumps_jf[b.filter.Len()] = jf

	code := Code(uint16(s) | uint16(0x30) | JMP)
	b.filter.append_insn(code, 0, 0, cmp)
	return b
}

// Append a JSET instruction to the filter.
func (b *Builder) JSET(s Src, jt, jf string, cmp uint32) *Builder {
	b.jumps_jt[b.filter.Len()] = jt
	b.jumps_jf[b.filter.Len()] = jf

	code := Code(uint16(s) | uint16(0x40) | JMP)
	b.filter.append_insn(code, 0, 0, cmp)
	return b
}

// Append a RET (return) instruction to the filter.
func (b *Builder) RET(s Src, bytes uint32) *Builder {
	code := Code(uint16(s) | RET)
	b.filter.append_insn(code, 0, 0, bytes)
	return b
}

// Append a TAX instruction to the filter.
func (b *Builder) TAX() *Builder {
	code := Code(uint16(0x00) | MISC)
	b.filter.append_insn(code, 0, 0, 0)
	return b
}

// Append a TXA instruction to the filter.
func (b *Builder) TXA() *Builder {
	code := Code(uint16(0x80) | MISC)
	b.filter.append_insn(code, 0, 0, 0)
	return b
}
