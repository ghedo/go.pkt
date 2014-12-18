all: bpf_asm

bpf_asm: bpf_asm.nn.go y.go
	go build -o bpf_asm bpf_asm.nn.go y.go

y.go: bpf_asm.y
	go tool yacc bpf_asm.y

bpf_asm.nn.go: bpf_asm.l
	nex bpf_asm.l
