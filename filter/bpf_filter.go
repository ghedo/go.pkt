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
