/ldb/	{ return OP_LDB }
/ldh/	{ return OP_LDH }
/ld/	{ return OP_LD }
/ldi/	{ return OP_LDI }
/ldx/	{ return OP_LDX }
/ldxi/	{ return OP_LDXI }
/ldxb/	{ return OP_LDXB }
/st/	{ return OP_ST }
/stx/	{ return OP_STX }
/jmp/	{ return OP_JMP }
/ja/	{ return OP_JMP }
/jeq/	{ return OP_JEQ }
/jneq/	{ return OP_JNEQ }
/jne/	{ return OP_JNEQ }
/jlt/	{ return OP_JLT }
/jle/	{ return OP_JLE }
/jgt/	{ return OP_JGT }
/jge/	{ return OP_JGE }
/jset/	{ return OP_JSET }
/add/	{ return OP_ADD }
/sub/	{ return OP_SUB }
/mul/	{ return OP_MUL }
/div/	{ return OP_DIV }
/neg/	{ return OP_NEG }
/and/	{ return OP_AND }
/or/	{ return OP_OR }
/lsh/	{ return OP_LSH }
/rsh/	{ return OP_RSH }
/ret/	{ return OP_RET }
/tax/	{ return OP_TAX }
/txa/	{ return OP_TXA }

/#?len/		{ return K_PKT_LEN }
/#?proto/	{ return K_PROTO }
/#?type/	{ return K_TYPE }
/#?poff/	{ return K_POFF }
/#?ifidx/	{ return K_IFIDX }
/#?nla/		{ return K_NLATTR }
/#?nlan/	{ return K_NLATTR_NEST }
/#?mark/	{ return K_MARK }
/#?queue/	{ return K_QUEUE }
/#?hatype/	{ return K_HATYPE }
/#?rxhash/	{ return K_RXHASH }
/#?cpu/		{ return K_CPU }
/#?vlan_tci/	{ return K_VLANT }
/#?vlan_pr/	{ return K_VLANP }

/:/		{ return ':' }
/,/		{ return ',' }
/#/		{ return '#' }
/%/		{ return '%' }
/\[/		{ return '[' }
/\]/		{ return ']' }
/\(/		{ return '(' }
/\)/		{ return ')' }
/x/		{ return 'x' }
/a/		{ return 'a' }
/\+/		{ return '+' }
/M/		{ return 'M' }
/\*/		{ return '*' }
/&/		{ return '&' }

/([0][x][a-fA-F0-9]+)/ {
	str := strings.TrimPrefix(yylex.Text(), "0x")
	num, _ := strconv.ParseUint(str, 16, 32)
	lval.number = uint32(num)
	return number
}

/([0][b][0-1]+)/ {
	str := strings.TrimPrefix(yylex.Text(), "0b")
	num, _ := strconv.ParseUint(str, 2, 32)
	lval.number = uint32(num)
	return number
}

/(([0])|([-+]?[1-9][0-9]*))/ {
	num, _ := strconv.ParseUint(yylex.Text(), 10, 32)
	lval.number = uint32(num)
	return number
}

/([0][0-9]+)/ {
	str := strings.TrimPrefix(yylex.Text(), "0")
	num, _ := strconv.ParseUint(str, 8, 32)
	lval.number = uint32(num)
	return number
}

/[a-zA-Z_][a-zA-Z0-9_]+/ 	{
	lval.label = yylex.Text()
	return label
}
//
package main

import "log"
import "strconv"
import "os"

import "github.com/docopt/docopt-go"

import "github.com/ghedo/go.pkt/filter"

var bld *filter.Builder

func main() {
	log.SetFlags(0)

	usage := `Usage: bpf_asm <file>`

	args, err := docopt.Parse(usage, nil, true, "", false)
	if err != nil {
		log.Fatalf("Invalid arguments: %s", err)
	}

	file, err := os.Open(args["<file>"].(string))
	if err != nil {
		log.Fatalf("Error opening file: %s", err)
	}

	bld = filter.NewBuilder()

	lex := NewLexer(file)
	yyParse(lex)

	flt := bld.Build()

	if !flt.Validate() {
		log.Fatalf("Invalid filter")
	}

	log.Println(flt)
}
