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

// Allocate and initialize a new Builder.
func NewBuilder() *Builder {
    b := &Builder{}

    b.filter   = &Filter{}
    b.labels   = make(map[string]int)
    b.jumps_k  = make(map[int]string)
    b.jumps_jt = make(map[int]string)
    b.jumps_jf = make(map[int]string)

    return b
}

// Generate and return the Filter associated with the Builder.
func (b *Builder) Build() *Filter {
    prog := (*C.struct_bpf_program)(b.filter.Program())
    flen := int(C.bpf_get_len(prog))

    for i := 0; i < flen; i++ {
        insn := C.bpf_get_insn(prog, C.int(i))

        if lbl, ok := b.jumps_k[i]; ok {
            addr := b.labels[lbl]
            if addr != 0 {
                insn.k = C.bpf_u_int32(addr - i - 1)
            }
        }

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

// Define a new label at the next instruction position. Labels are used in jump
// instructions to identify the jump target.
func (b *Builder) Label(name string) *Builder {
    b.labels[name] = b.filter.Len()
    return b
}

// Append an LD instruction to the filter, which loads a value of size s into
// the accumulator. m represents the addressing mode of the source operand and
// can be IMM (load a constant value), ABS (load packet data at the given fixed
// offset), IND (load packet data at the given relative offset), LEN (load the
// packet length or MEM (load a value from memory at the given offset).
func (b *Builder) LD(s Size, m Mode, val uint32) *Builder {
    code := Code(uint16(s) | uint16(m)) | LD
    b.filter.append_insn(code, 0, 0, val)
    return b
}

// Append a LDX (load index) instruction to the filter, which loads a value of
// size s into the index register. m represents the addressing mode of the
// source operand and can be IMM (load a constant value), LEN (load the packet
// length, MEM (load a value from memory at the given offset) or MSH (load the
// length of the IP header).
func (b *Builder) LDX(s Size, m Mode, val uint32) *Builder {
    code := Code(uint16(s) | uint16(m) | LDX)
    b.filter.append_insn(code, 0, 0, val)
    return b
}

// Append a ST (store) instruction to the filter, which stores the value of the
// accumulator in memory at the given offset.
func (b *Builder) ST(off uint32) *Builder {
    b.filter.append_insn(ST, 0, 0, off)
    return b
}

// Append a STX (store index) instruction to the filter, which stores the value
// of the index register in memory at the given offset.
func (b *Builder) STX(off uint32) *Builder {
    b.filter.append_insn(STX, 0, 0, off)
    return b
}

// Append an ADD instruction to the filter, which adds a value to the
// accumulator. s represents the source operand type and can be either Const
// (which adds the supplied value) or Index (which adds the index register
// value).
func (b *Builder) ADD(s Src, val uint32) *Builder {
    code := Code(uint16(s) | uint16(0x00) | ALU)
    b.filter.append_insn(code, 0, 0, val)
    return b
}

// Append a SUB instruction to the filter, which subtracts a value from the
// accumulator. s represents the source operand type and can be either Const
// (which subtracts the supplied value) or Index (which subtracts the index
// register value).
func (b *Builder) SUB(s Src, val uint32) *Builder {
    code := Code(uint16(s) | uint16(0x10) | ALU)
    b.filter.append_insn(code, 0, 0, val)
    return b
}

// Append a MUL instruction to the filter, which multiplies a value to the
// accumulator. s represents the source operand type and can be either Const
// (which multiplies the supplied value) or Index (which multiplies the index
// register value).
func (b *Builder) MUL(s Src, val uint32) *Builder {
    code := Code(uint16(s) | uint16(0x20) | ALU)
    b.filter.append_insn(code, 0, 0, val)
    return b
}

// Append a DIV instruction to the filter, which divides the accumulator by a
// value. s represents the source operand type and can be either Const (which
// divides by the supplied value) or Index (which divides by the index register
// value).
func (b *Builder) DIV(s Src, val uint32) *Builder {
    code := Code(uint16(s) | uint16(0x30) | ALU)
    b.filter.append_insn(code, 0, 0, val)
    return b
}

// Append an OR instruction to the filter, which performs the binary "or"
// between the accumulator and a value. s represents the source operand type and
// can be either Const (which uses the supplied value) or Index (which uses the
// index register value).
func (b *Builder) OR(s Src, val uint32) *Builder {
    code := Code(uint16(s) | uint16(0x40) | ALU)
    b.filter.append_insn(code, 0, 0, val)
    return b
}

// Append an AND instruction to the filter, which performs the binary "and"
// between the accumulator and a value. s represents the source operand type and
// can be either Const (which uses the supplied value) or Index (which uses the
// index register value).
func (b *Builder) AND(s Src, val uint32) *Builder {
    code := Code(uint16(s) | uint16(0x50) | ALU)
    b.filter.append_insn(code, 0, 0, val)
    return b
}

// Append an LSH instruction to the filter, which shifts to the left the
// accumulator register by a value. s represents the source operand type and can
// be either Const (which shifts by the supplied value) or Index (which shifts
// by the index register value).
func (b *Builder) LSH(s Src, val uint32) *Builder {
    code := Code(uint16(s) | uint16(0x60) | ALU)
    b.filter.append_insn(code, 0, 0, val)
    return b
}

// Append an RSH instruction to the filter, which shifts to the right the
// accumulator register by a value. s represents the source operand type and can
// be either Const (which shifts by the supplied value) or Index (which shifts
// by the index register value).
func (b *Builder) RSH(s Src, val uint32) *Builder {
    code := Code(uint16(s) | uint16(0x70) | ALU)
    b.filter.append_insn(code, 0, 0, val)
    return b
}

// Append a NEG instruction to the filter which negates the accumulator.
func (b *Builder) NEG() *Builder {
    code := Code(uint16(0x80) | ALU)
    b.filter.append_insn(code, 0, 0, 0)
    return b
}

// Append a MOD instruction to the filter, which computes the accumulator modulo a
// value. s represents the source operand type and can be either Const (which
// divides by the supplied value) or Index (which divides by the index register
// value).
func (b *Builder) MOD(s Src, val uint32) *Builder {
    code := Code(uint16(s) | uint16(0x90) | ALU)
    b.filter.append_insn(code, 0, 0, val)
    return b
}

// Append an XOR instruction to the filter, which performs the binary "xor"
// between the accumulator and a value. s represents the source operand type and
// can be either Const (which uses the supplied value) or Index (which uses the
// index register value).
func (b *Builder) XOR(s Src, val uint32) *Builder {
    code := Code(uint16(s) | uint16(0xa0) | ALU)
    b.filter.append_insn(code, 0, 0, val)
    return b
}

// Append a JA instruction to the filter, which performs a jump to the given
// label.
func (b *Builder) JA(j string) *Builder {
    b.jumps_k[b.filter.Len()] = j

    code := Code(uint16(0x00) | JMP)
    b.filter.append_insn(code, 0, 0, 0)
    return b
}

// Append a JEQ instruction to the filter, which performs a jump to the jt label
// if the accumulator value equals cmp (if s is Const) or the index register (if
// s is Index), otherwise jumps to jf.
func (b *Builder) JEQ(s Src, jt, jf string, cmp uint32) *Builder {
    b.jumps_jt[b.filter.Len()] = jt
    b.jumps_jf[b.filter.Len()] = jf

    code := Code(uint16(s) | uint16(0x10) | JMP)
    b.filter.append_insn(code, 0, 0, cmp)
    return b
}

// Append a JGT instruction to the filter, which performs a jump to the jt label
// if the accumulator value is greater than cmp (if s is Const) or the index
// register (if s is Index), otherwise jumps to jf.
func (b *Builder) JGT(s Src, jt, jf string, cmp uint32) *Builder {
    b.jumps_jt[b.filter.Len()] = jt
    b.jumps_jf[b.filter.Len()] = jf

    code := Code(uint16(s) | uint16(0x20) | JMP)
    b.filter.append_insn(code, 0, 0, cmp)
    return b
}

// Append a JGE instruction to the filter, which performs a jump to the jt label
// if the accumulator value is greater than or equals cmp (if s is Const) or the
// index register (if s is Index), otherwise jumps to jf.
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

// Append a RET instruction to the filter, which terminates the filter program
// and specifies the amount of the packet to accept. s represents the source
// operand type and can be either Const (which returns the supplied value) or
// Acc (which returns the accumulator value).
func (b *Builder) RET(s Src, bytes uint32) *Builder {
    code := Code(uint16(s) | RET)
    b.filter.append_insn(code, 0, 0, bytes)
    return b
}

// Append a TAX instruction to the filter. TAX transfers the accumulator value
// into the index register.
func (b *Builder) TAX() *Builder {
    code := Code(uint16(0x00) | MISC)
    b.filter.append_insn(code, 0, 0, 0)
    return b
}

// Append a TXA instruction to the filter. TXA transfers the index register
// value into the accumulator.
func (b *Builder) TXA() *Builder {
    code := Code(uint16(0x80) | MISC)
    b.filter.append_insn(code, 0, 0, 0)
    return b
}

// Append a raw BPF instruction
func (b *Builder) AppendInstruction(code Code, jt, jf uint8, k uint32) *Builder {
    b.filter.append_insn(code, jt, jf, k)
    return b
}
