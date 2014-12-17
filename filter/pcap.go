package filter

// #cgo LDFLAGS: -lpcap
// #include <stdlib.h>
// #include <pcap.h>
import "C"

import "fmt"
import "unsafe"

import "github.com/ghedo/hype/packet"

// Compile the given tcpdump-like expression to a BPF filter.
func Compile(filter string, link_type packet.Type) (*Filter, error) {
	f := &Filter{}

	fil_str := C.CString(filter)
	defer C.free(unsafe.Pointer(fil_str))

	err_str := (*C.char)(C.calloc(256, 1))
	defer C.free(unsafe.Pointer(err_str))

	pcap_type := link_type.ToLinkType()

	err := C.pcap_compile_nopcap(
		C.int(0x7fff), C.int(pcap_type),
		(*C.struct_bpf_program)(f),
		fil_str, 0, 0xffffffff,
	)
	if err < 0 {
		return nil, fmt.Errorf("Could not compile filter")
	}

	return f, nil
}
