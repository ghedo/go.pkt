package filter

// #cgo LDFLAGS: -lpcap
// #include <stdlib.h>
// #include <pcap.h>
import "C"

import "fmt"
import "unsafe"

import "github.com/ghedo/hype/packet"

type Filter struct {
	bpf C.struct_bpf_program
}

func Compile(filter string, link_type packet.Type) (*Filter, error) {
	f := &Filter{}

	fil_str := C.CString(filter)
	defer C.free(unsafe.Pointer(fil_str))

	err_str := (*C.char)(C.calloc(256, 1))
	defer C.free(unsafe.Pointer(err_str))

	pcap_type := link_type.ToLinkType()

	err := C.pcap_compile_nopcap(
		C.int(0x7fff), C.int(pcap_type), &f.bpf,
		fil_str, 0, 0xffffffff,
	)
	if err < 0 {
		return nil, fmt.Errorf("Could not compile filter")
	}

	return f, nil
}

func (f *Filter) Match(raw_pkt []byte) bool {
	var hdr C.struct_pcap_pkthdr

	hdr.ts.tv_sec  = 0
	hdr.ts.tv_usec = 0
	hdr.caplen     = C.bpf_u_int32(len(raw_pkt))
	hdr.len        = C.bpf_u_int32(hdr.caplen)
	data          := (*C.u_char)(unsafe.Pointer(&raw_pkt[0]))

	return C.pcap_offline_filter(&f.bpf, &hdr, data) != 0
}

func (f *Filter) Close() {
	C.pcap_freecode(&f.bpf)
}
