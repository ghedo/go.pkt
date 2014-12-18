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
	: label ':' { bld.Label($1)
	}
	;

ldb
	: OP_LDB '[' 'x' '+' number ']' {
		bld.LD(filter.Byte, filter.IND, $5)
	}
	| OP_LDB '[' '%' 'x' '+' number ']' {
		bld.LD(filter.Byte, filter.IND, $6)
	}
	| OP_LDB '[' number ']' {
		bld.LD(filter.Byte, filter.ABS, $3)
	}
	;

ldh
	: OP_LDH '[' 'x' '+' number ']' {
		bld.LD(filter.Half, filter.IND, $5)
	}
	| OP_LDH '[' '%' 'x' '+' number ']' {
		bld.LD(filter.Half, filter.IND, $6)
	}
	| OP_LDH '[' number ']' {
		bld.LD(filter.Half, filter.ABS, $3)
	}
	;

ldi
	: OP_LDI '#' number {
		bld.LD(filter.Word, filter.IMM, $3)
	}
	| OP_LDI number {
		bld.LD(filter.Word, filter.IMM, $2)
	}
	;

ld
	: OP_LD '#' number {
		bld.LD(filter.Word, filter.IMM, $3)
	}
	| OP_LD K_PKT_LEN {
		bld.LD(filter.Word, filter.LEN, 0)
	}
	| OP_LD 'M' '[' number ']' {
		bld.LD(filter.Word, filter.MEM, $4)
	}
	| OP_LD '[' 'x' '+' number ']' {
		bld.LD(filter.Word, filter.IND, $5)
	}
	| OP_LD '[' '%' 'x' '+' number ']' {
		bld.LD(filter.Word, filter.IND, $6)
	}
	| OP_LD '[' number ']' {
		bld.LD(filter.Word, filter.ABS, $3)
	}
	;

ldxi
	: OP_LDXI '#' number {
		bld.LDX(filter.Word, filter.IMM, $3)
	}
	| OP_LDXI number {
		bld.LDX(filter.Word, filter.IMM, $2)
	}
	;

ldx
	: OP_LDX '#' number {
		bld.LDX(filter.Word, filter.IMM, $3)
	}
	| OP_LDX K_PKT_LEN {
		bld.LDX(filter.Word, filter.LEN, 0)
	}
	| OP_LDX 'M' '[' number ']' {
		bld.LDX(filter.Word, filter.MEM, $4)
	}
	| OP_LDXB number '*' '(' '[' number ']' '&' number ')' {
		if ($2 != 4 || $9 != 0xf) {
			yylex.Error("ldxb offset not supported!")
		} else {
			bld.LDX(filter.Byte, filter.MSH, $6)
		}
	}
	| OP_LDX number '*' '(' '[' number ']' '&' number ')' {
		if ($2 != 4 || $9 != 0xf) {
			yylex.Error("ldxb offset not supported!")
		} else {
			bld.LDX(filter.Byte, filter.MSH, $6)
		}
	}
	;

st
	: OP_ST 'M' '[' number ']' {
		bld.ST($4)
	}
	;

stx
	: OP_STX 'M' '[' number ']' {
		bld.STX($4)
	}
	;

jmp
	: OP_JMP label {
		bld.JA($2)
	}
	;

jeq
	: OP_JEQ '#' number ',' label ',' label {
		bld.JEQ(filter.Const, $5, $7, $3)
	}
	| OP_JEQ 'x' ',' label ',' label {
		bld.JEQ(filter.Index, $4, $6, 0)
	}
	| OP_JEQ '%' 'x' ',' label ',' label {
		bld.JEQ(filter.Index, $5, $7, 0)
	}
	| OP_JEQ '#' number ',' label {
		bld.JEQ(filter.Const, "", $5, $3)
	}
	| OP_JEQ 'x' ',' label {
		bld.JEQ(filter.Index, "", $4, 0)
	}
	| OP_JEQ '%' 'x' ',' label {
		bld.JEQ(filter.Index, "", $5, 0)
	}
	;

jneq
	: OP_JNEQ '#' number ',' label {
		bld.JEQ(filter.Const, "", $5, $3)
	}
	| OP_JNEQ 'x' ',' label {
		bld.JEQ(filter.Index, "", $4, 0)
	}
	| OP_JNEQ '%' 'x' ',' label {
		bld.JEQ(filter.Index, "", $5, 0)
	}
	;

jlt
	: OP_JLT '#' number ',' label {
		bld.JGE(filter.Const, "", $5, $3)
	}
	| OP_JLT 'x' ',' label {
		bld.JGE(filter.Index, "", $4, 0)
	}
	| OP_JLT '%' 'x' ',' label {
		bld.JGE(filter.Index, "", $5, 0)
	}
	;

jle
	: OP_JLE '#' number ',' label {
		bld.JGT(filter.Const, "", $5, $3)
	}
	| OP_JLE 'x' ',' label {
		bld.JGT(filter.Index, "", $4, 0)
	}
	| OP_JLE '%' 'x' ',' label {
		bld.JGT(filter.Index, "", $5, 0)
	}
	;

jgt
	: OP_JGT '#' number ',' label ',' label {
		bld.JGT(filter.Const, $5, $7, $3)
	}
	| OP_JGT 'x' ',' label ',' label {
		bld.JGT(filter.Index, $4, $6, 0)
	}
	| OP_JGT '%' 'x' ',' label ',' label {
		bld.JGT(filter.Index, $5, $7, 0)
	}
	| OP_JGT '#' number ',' label {
		bld.JGT(filter.Const, "", $5, $3)
	}
	| OP_JGT 'x' ',' label {
		bld.JGT(filter.Index, "", $4, 0)
	}
	| OP_JGT '%' 'x' ',' label {
		bld.JGT(filter.Index, "", $5, 0)
	}
	;

jge
	: OP_JGE '#' number ',' label ',' label {
		bld.JGE(filter.Const, $5, $7, $3)
	}
	| OP_JGE 'x' ',' label ',' label {
		bld.JGE(filter.Index, $4, $6, 0)
	}
	| OP_JGE '%' 'x' ',' label ',' label {
		bld.JGE(filter.Index, $5, $7, 0)
	}
	| OP_JGE '#' number ',' label {
		bld.JGE(filter.Const, "", $5, $3)
	}
	| OP_JGE 'x' ',' label {
		bld.JGE(filter.Index, "", $4, 0)
	}
	| OP_JGE '%' 'x' ',' label {
		bld.JGE(filter.Index, "", $5, 0)
	}
	;

jset
	: OP_JSET '#' number ',' label ',' label {
		bld.JSET(filter.Const, $5, $7, $3)
	}
	| OP_JSET 'x' ',' label ',' label {
		bld.JSET(filter.Index, $4, $6, 0)
	}
	| OP_JSET '%' 'x' ',' label ',' label {
		bld.JSET(filter.Index, $5, $7, 0)
	}
	| OP_JSET '#' number ',' label {
		bld.JSET(filter.Const, "", $5, $3)
	}
	| OP_JSET 'x' ',' label {
		bld.JSET(filter.Index, "", $4, 0)
	}
	| OP_JSET '%' 'x' ',' label {
		bld.JSET(filter.Index, "", $5, 0)
	}
	;

add
	: OP_ADD '#' number {
		bld.ADD(filter.Const, $3)
	}
	| OP_ADD 'x' {
		bld.ADD(filter.Index, 0)
	}
	| OP_ADD '%' 'x' {
		bld.ADD(filter.Index, 0)
	}
	;

sub
	: OP_SUB '#' number {
		bld.SUB(filter.Const, $3)
	}
	| OP_SUB 'x' {
		bld.SUB(filter.Index, 0)
	}
	| OP_SUB '%' 'x' {
		bld.SUB(filter.Index, 0)
	}
	;

mul
	: OP_MUL '#' number {
		bld.MUL(filter.Const, $3)
	}
	| OP_MUL 'x' {
		bld.MUL(filter.Index, 0)
	}
	| OP_MUL '%' 'x' {
		bld.MUL(filter.Index, 0)
	}
	;

div
	: OP_DIV '#' number {
		bld.DIV(filter.Const, $3)
	}
	| OP_DIV 'x' {
		bld.DIV(filter.Index, 0)
	}
	| OP_DIV '%' 'x' {
		bld.DIV(filter.Index, 0)
	}
	;

neg
	: OP_NEG {
		bld.NEG()
	}
	;

and
	: OP_AND '#' number {
		bld.AND(filter.Const, $3)
	}
	| OP_AND 'x' {
		bld.AND(filter.Index, 0)
	}
	| OP_AND '%' 'x' {
		bld.AND(filter.Index, 0)
	}
	;

or
	: OP_OR '#' number {
		bld.OR(filter.Const, $3)
	}
	| OP_OR 'x' {
		bld.OR(filter.Index, 0)
	}
	| OP_OR '%' 'x' {
		bld.OR(filter.Index, 0)
	}
	;

lsh
	: OP_LSH '#' number {
		bld.LSH(filter.Const, $3)
	}
	| OP_LSH 'x' {
		bld.LSH(filter.Index, 0)
	}
	| OP_LSH '%' 'x' {
		bld.LSH(filter.Index, 0)
	}
	;

rsh
	: OP_RSH '#' number {
		bld.RSH(filter.Const, $3)
	}
	| OP_RSH 'x' {
		bld.RSH(filter.Index, 0)
	}
	| OP_RSH '%' 'x' {
		bld.RSH(filter.Index, 0)
	}
	;

ret
	: OP_RET 'a' {
		bld.RET(filter.Acc, 0)
	}
	| OP_RET '%' 'a' {
		bld.RET(filter.Acc, 0)
	}
	| OP_RET 'x' {
		bld.RET(filter.Index, 0)
	}
	| OP_RET '%' 'x' {
		bld.RET(filter.Index, 0)
	}
	| OP_RET '#' number {
		bld.RET(filter.Const, $3)
	}
	;

tax
	: OP_TAX {
		bld.TAX()
	}
	;

txa
	: OP_TXA {
		bld.TXA()
	}
	;

%%
