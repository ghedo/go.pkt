// Provides an API for compiling and manipulating BPF filters.
package filter

// #cgo LDFLAGS: -lpcap
// #include <stdlib.h>
// #include <pcap.h>
import "C"

import "fmt"
import "unsafe"

import "github.com/ghedo/hype/packet"

type Filter C.struct_bpf_program

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

// Try to match the given buffer against the filter.
func (f *Filter) Match(raw_pkt []byte) bool {
	var hdr C.struct_pcap_pkthdr

	hdr.ts.tv_sec  = 0
	hdr.ts.tv_usec = 0
	hdr.caplen     = C.bpf_u_int32(len(raw_pkt))
	hdr.len        = C.bpf_u_int32(hdr.caplen)
	data          := (*C.u_char)(unsafe.Pointer(&raw_pkt[0]))

	bpf := (*C.struct_bpf_program)(f)
	return C.pcap_offline_filter(bpf, &hdr, data) != 0
}

// Deallocate the filter.
func (f *Filter) Cleanup() {
	C.pcap_freecode((*C.struct_bpf_program)(f))
}
