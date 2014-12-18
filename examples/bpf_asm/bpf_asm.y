%{
package main

import "github.com/ghedo/hype/filter"
%}

%union {
	label  string
	number uint32
}

%token OP_LDB
%token OP_LDH
%token OP_LD
%token OP_LDI
%token OP_LDX
%token OP_LDXI
%token OP_LDXB
%token OP_ST
%token OP_STX
%token OP_JMP
%token OP_JEQ
%token OP_JNEQ
%token OP_JLT
%token OP_JLE
%token OP_JGT
%token OP_JGE
%token OP_JSET
%token OP_ADD
%token OP_SUB
%token OP_MUL
%token OP_DIV
%token OP_NEG
%token OP_AND
%token OP_OR
%token OP_LSH
%token OP_RSH
%token OP_RET
%token OP_TAX
%token OP_TXA

%token K_PKT_LEN
%token K_PROTO
%token K_TYPE
%token K_POFF
%token K_IFIDX
%token K_NLATTR
%token K_NLATTR_NEST
%token K_MARK
%token K_QUEUE
%token K_HATYPE
%token K_RXHASH
%token K_CPU
%token K_VLANT
%token K_VLANP

%token number
%token label

%token jtl
%token jfl
%token jkl

%token ':' ',' '[' ']' '(' ')' 'x' 'a' '+' 'M' '*' '&' '#' '%'

%type <label> label
%type <number> number

%%

prog
	: line
	| prog line
	;

line
	: instr
	| labelled_instr
	;

labelled_instr
	: labelled instr
	;

instr
	: ldb
	| ldh
	| ld
	| ldi
	| ldx
	| ldxi
	| st
	| stx
	| jmp
	| jeq
	| jneq
	| jlt
	| jle
	| jgt
	| jge
	| jset
	| add
	| sub
	| mul
	| div
	| neg
	| and
	| or
	| lsh
	| rsh
	| ret
	| tax
	| txa
	;

labelled
	: label ':' { lbl[$1] = uint8(flt.Len())
	}
	;

ldb
	: OP_LDB '[' 'x' '+' number ']' {
		flt.LD(filter.Byte, filter.IND, $5)
	}
	| OP_LDB '[' '%' 'x' '+' number ']' {
		flt.LD(filter.Byte, filter.IND, $6)
	}
	| OP_LDB '[' number ']' {
		flt.LD(filter.Byte, filter.ABS, $3)
	}
	;

ldh
	: OP_LDH '[' 'x' '+' number ']' {
		flt.LD(filter.Half, filter.IND, $5)
	}
	| OP_LDH '[' '%' 'x' '+' number ']' {
		flt.LD(filter.Half, filter.IND, $6)
	}
	| OP_LDH '[' number ']' {
		flt.LD(filter.Half, filter.ABS, $3)
	}
	;

ldi
	: OP_LDI '#' number {
		flt.LD(filter.Word, filter.IMM, $3)
	}
	| OP_LDI number {
		flt.LD(filter.Word, filter.IMM, $2)
	}
	;

ld
	: OP_LD '#' number {
		flt.LD(filter.Word, filter.IMM, $3)
	}
	| OP_LD K_PKT_LEN {
		flt.LD(filter.Word, filter.LEN, 0)
	}
	| OP_LD 'M' '[' number ']' {
		flt.LD(filter.Word, filter.MEM, $4)
	}
	| OP_LD '[' 'x' '+' number ']' {
		flt.LD(filter.Word, filter.IND, $5)
	}
	| OP_LD '[' '%' 'x' '+' number ']' {
		flt.LD(filter.Word, filter.IND, $6)
	}
	| OP_LD '[' number ']' {
		flt.LD(filter.Word, filter.ABS, $3)
	}
	;

ldxi
	: OP_LDXI '#' number {
		flt.LDX(filter.Word, filter.IMM, $3)
	}
	| OP_LDXI number {
		flt.LDX(filter.Word, filter.IMM, $2)
	}
	;

ldx
	: OP_LDX '#' number {
		flt.LDX(filter.Word, filter.IMM, $3)
	}
	| OP_LDX K_PKT_LEN {
		flt.LDX(filter.Word, filter.LEN, 0)
	}
	| OP_LDX 'M' '[' number ']' {
		flt.LDX(filter.Word, filter.MEM, $4)
	}
	| OP_LDXB number '*' '(' '[' number ']' '&' number ')' {
		if ($2 != 4 || $9 != 0xf) {
			yylex.Error("ldxb offset not supported!")
		} else {
			flt.LDX(filter.Byte, filter.MSH, $6)
		}
	}
	| OP_LDX number '*' '(' '[' number ']' '&' number ')' {
		if ($2 != 4 || $9 != 0xf) {
			yylex.Error("ldxb offset not supported!")
		} else {
			flt.LDX(filter.Byte, filter.MSH, $6)
		}
	}
	;

st
	: OP_ST 'M' '[' number ']' {
		flt.ST($4)
	}
	;

stx
	: OP_STX 'M' '[' number ']' {
		flt.STX($4)
	}
	;

jmp
	: OP_JMP label {
		flt.JA(jmpl(flt, $2))
	}
	;

jeq
	: OP_JEQ '#' number ',' label ',' label {
		flt.JEQ(filter.Const, jmpl(flt, $5), jmpl(flt, $7), $3)
	}
	| OP_JEQ 'x' ',' label ',' label {
		flt.JEQ(filter.Index, jmpl(flt, $4), jmpl(flt, $6), 0)
	}
	| OP_JEQ '%' 'x' ',' label ',' label {
		flt.JEQ(filter.Index, jmpl(flt, $5), jmpl(flt, $7), 0)
	}
	| OP_JEQ '#' number ',' label {
		flt.JEQ(filter.Const, 0, jmpl(flt, $5), $3)
	}
	| OP_JEQ 'x' ',' label {
		flt.JEQ(filter.Index, 0, jmpl(flt, $4), 0)
	}
	| OP_JEQ '%' 'x' ',' label {
		flt.JEQ(filter.Index, 0, jmpl(flt, $5), 0)
	}
	;

jneq
	: OP_JNEQ '#' number ',' label {
		flt.JEQ(filter.Const, 0, jmpl(flt, $5), $3)
	}
	| OP_JNEQ 'x' ',' label {
		flt.JEQ(filter.Index, 0, jmpl(flt, $4), 0)
	}
	| OP_JNEQ '%' 'x' ',' label {
		flt.JEQ(filter.Index, 0, jmpl(flt, $5), 0)
	}
	;

jlt
	: OP_JLT '#' number ',' label {
		flt.JGE(filter.Const, 0, jmpl(flt, $5), $3)
	}
	| OP_JLT 'x' ',' label {
		flt.JGE(filter.Index, 0, jmpl(flt, $4), 0)
	}
	| OP_JLT '%' 'x' ',' label {
		flt.JGE(filter.Index, 0, jmpl(flt, $5), 0)
	}
	;

jle
	: OP_JLE '#' number ',' label {
		flt.JGT(filter.Const, 0, jmpl(flt, $5), $3)
	}
	| OP_JLE 'x' ',' label {
		flt.JGT(filter.Index, 0, jmpl(flt, $4), 0)
	}
	| OP_JLE '%' 'x' ',' label {
		flt.JGT(filter.Index, 0, jmpl(flt, $5), 0)
	}
	;

jgt
	: OP_JGT '#' number ',' label ',' label {
		flt.JGT(filter.Const, jmpl(flt, $5), jmpl(flt, $7), $3)
	}
	| OP_JGT 'x' ',' label ',' label {
		flt.JGT(filter.Index, jmpl(flt, $4), jmpl(flt, $6), 0)
	}
	| OP_JGT '%' 'x' ',' label ',' label {
		flt.JGT(filter.Index, jmpl(flt, $5), jmpl(flt, $7), 0)
	}
	| OP_JGT '#' number ',' label {
		flt.JGT(filter.Const, 0, jmpl(flt, $5), $3)
	}
	| OP_JGT 'x' ',' label {
		flt.JGT(filter.Index, 0, jmpl(flt, $4), 0)
	}
	| OP_JGT '%' 'x' ',' label {
		flt.JGT(filter.Index, 0, jmpl(flt, $5), 0)
	}
	;

jge
	: OP_JGE '#' number ',' label ',' label {
		flt.JGE(filter.Const, jmpl(flt, $5), jmpl(flt, $7), $3)
	}
	| OP_JGE 'x' ',' label ',' label {
		flt.JGE(filter.Index, jmpl(flt, $4), jmpl(flt, $6), 0)
	}
	| OP_JGE '%' 'x' ',' label ',' label {
		flt.JGE(filter.Index, jmpl(flt, $5), jmpl(flt, $7), 0)
	}
	| OP_JGE '#' number ',' label {
		flt.JGE(filter.Const, 0, jmpl(flt, $5), $3)
	}
	| OP_JGE 'x' ',' label {
		flt.JGE(filter.Index, 0, jmpl(flt, $4), 0)
	}
	| OP_JGE '%' 'x' ',' label {
		flt.JGE(filter.Index, 0, jmpl(flt, $5), 0)
	}
	;

jset
	: OP_JSET '#' number ',' label ',' label {
		flt.JSET(filter.Const, jmpl(flt, $5), jmpl(flt, $7), $3)
	}
	| OP_JSET 'x' ',' label ',' label {
		flt.JSET(filter.Index, jmpl(flt, $4), jmpl(flt, $6), 0)
	}
	| OP_JSET '%' 'x' ',' label ',' label {
		flt.JSET(filter.Index, jmpl(flt, $5), jmpl(flt, $7), 0)
	}
	| OP_JSET '#' number ',' label {
		flt.JSET(filter.Const, 0, jmpl(flt, $5), $3)
	}
	| OP_JSET 'x' ',' label {
		flt.JSET(filter.Index, 0, jmpl(flt, $4), 0)
	}
	| OP_JSET '%' 'x' ',' label {
		flt.JSET(filter.Index, 0, jmpl(flt, $5), 0)
	}
	;

add
	: OP_ADD '#' number {
		flt.ADD(filter.Const, $3)
	}
	| OP_ADD 'x' {
		flt.ADD(filter.Index, 0)
	}
	| OP_ADD '%' 'x' {
		flt.ADD(filter.Index, 0)
	}
	;

sub
	: OP_SUB '#' number {
		flt.SUB(filter.Const, $3)
	}
	| OP_SUB 'x' {
		flt.SUB(filter.Index, 0)
	}
	| OP_SUB '%' 'x' {
		flt.SUB(filter.Index, 0)
	}
	;

mul
	: OP_MUL '#' number {
		flt.MUL(filter.Const, $3)
	}
	| OP_MUL 'x' {
		flt.MUL(filter.Index, 0)
	}
	| OP_MUL '%' 'x' {
		flt.MUL(filter.Index, 0)
	}
	;

div
	: OP_DIV '#' number {
		flt.DIV(filter.Const, $3)
	}
	| OP_DIV 'x' {
		flt.DIV(filter.Index, 0)
	}
	| OP_DIV '%' 'x' {
		flt.DIV(filter.Index, 0)
	}
	;

neg
	: OP_NEG {
		flt.NEG()
	}
	;

and
	: OP_AND '#' number {
		flt.AND(filter.Const, $3)
	}
	| OP_AND 'x' {
		flt.AND(filter.Index, 0)
	}
	| OP_AND '%' 'x' {
		flt.AND(filter.Index, 0)
	}
	;

or
	: OP_OR '#' number {
		flt.OR(filter.Const, $3)
	}
	| OP_OR 'x' {
		flt.OR(filter.Index, 0)
	}
	| OP_OR '%' 'x' {
		flt.OR(filter.Index, 0)
	}
	;

lsh
	: OP_LSH '#' number {
		flt.LSH(filter.Const, $3)
	}
	| OP_LSH 'x' {
		flt.LSH(filter.Index, 0)
	}
	| OP_LSH '%' 'x' {
		flt.LSH(filter.Index, 0)
	}
	;

rsh
	: OP_RSH '#' number {
		flt.RSH(filter.Const, $3)
	}
	| OP_RSH 'x' {
		flt.RSH(filter.Index, 0)
	}
	| OP_RSH '%' 'x' {
		flt.RSH(filter.Index, 0)
	}
	;

ret
	: OP_RET 'a' {
		flt.RET(filter.Acc, 0)
	}
	| OP_RET '%' 'a' {
		flt.RET(filter.Acc, 0)
	}
	| OP_RET 'x' {
		flt.RET(filter.Index, 0)
	}
	| OP_RET '%' 'x' {
		flt.RET(filter.Index, 0)
	}
	| OP_RET '#' number {
		flt.RET(filter.Const, $3)
	}
	;

tax
	: OP_TAX {
		flt.TAX()
	}
	;

txa
	: OP_TXA {
		flt.TXA()
	}
	;

%%
