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

// #cgo LDFLAGS: -lpcap
// #include <stdlib.h>
// #include <pcap.h>
import "C"

import "fmt"
import "unsafe"

import "github.com/ghedo/go.pkt/packet"

// Compile the given tcpdump-like expression to a BPF filter.
func Compile(filter string, link_type packet.Type, optimize bool) (*Filter, error) {
	var do_optimize int

	if optimize {
		do_optimize = 1
	} else {
		do_optimize = 0
	}

	f := &Filter{}

	filter_str := C.CString(filter)
	defer C.free(unsafe.Pointer(filter_str))

	pcap_type := link_type.ToLinkType()

	err := C.pcap_compile_nopcap(
		C.int(0x7fff), C.int(pcap_type),
		(*C.struct_bpf_program)(f.Program()),
		filter_str, C.int(do_optimize), 0xffffffff,
	)
	if err < 0 {
		return nil, fmt.Errorf("Could not compile filter")
	}

	return f, nil
}
