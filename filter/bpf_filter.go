// Provides an API for compiling and manipulating BPF filters.
package filter

// #include <stdlib.h>
// #include "bpf_filter.h"
import "C"

import "unsafe"

type Filter C.struct_bpf_program

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
