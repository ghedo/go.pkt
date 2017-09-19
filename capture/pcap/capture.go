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

// Provides packet capturing and injection on live network interfaces via
// libpcap.
package pcap

// #cgo LDFLAGS: -lpcap
// #include <stdlib.h>
// #include <pcap.h>
import "C"

import "fmt"
import "unsafe"

import "github.com/ghedo/go.pkt/filter"
import "github.com/ghedo/go.pkt/packet"

type Handle struct {
    Device string
    pcap   *C.pcap_t
}

// Create a new capture handle from the given network interface. Noe that this
// may require root privileges.
func Open(dev_name string) (*Handle, error) {
    handle := &Handle{ Device: dev_name }

    dev_str := C.CString(dev_name)
    defer C.free(unsafe.Pointer(dev_str))

    err_str := (*C.char)(C.calloc(256, 1))
    defer C.free(unsafe.Pointer(err_str))

    handle.pcap = C.pcap_create(dev_str, err_str)
    if handle == nil {
        return nil, fmt.Errorf(
            "Could not open device: %s", C.GoString(err_str),
        )
    }

    return handle, nil
}

// Return the link type of the capture handle (that is, the type of packets that
// come out of the packet source).
func (h *Handle) LinkType() packet.Type {
    return packet.LinkType(uint32(C.pcap_datalink(h.pcap)))
}

func (h *Handle) SetMTU(mtu int) error {
    err := C.pcap_set_snaplen(h.pcap, C.int(mtu))
    if err < 0 {
        return fmt.Errorf("Handle already active")
    }

    return nil
}

// Enable/disable promiscuous mode.
func (h *Handle) SetPromiscMode(promisc bool) error {
    var promisc_int C.int

    if promisc {
        promisc_int = 1
    } else {
        promisc_int = 0
    }

    err := C.pcap_set_promisc(h.pcap, promisc_int)
    if err < 0 {
        return fmt.Errorf("Handle already active")
    }

    return nil
}

// Enable/disable monitor mode. This is only relevant to RF-based packet sources
// (e.g. a WiFi or Bluetooth network interface)
func (h *Handle) SetMonitorMode(monitor bool) error {
    var rfmon_int C.int

    if monitor {
        rfmon_int = 1
    } else {
        rfmon_int = 0
    }

    err := C.pcap_set_rfmon(h.pcap, rfmon_int)
    if err < 0 {
        return fmt.Errorf("Handle already active")
    }

    return nil
}

// Apply the given filter it to the packet source. Only packets that match this
// filter will be captured.
func (h *Handle) ApplyFilter(filter *filter.Filter) error {
    if !filter.Validate() {
        return fmt.Errorf("Invalid filter")
    }

    err_str := (*C.char)(C.calloc(256, 1))
    defer C.free(unsafe.Pointer(err_str))

    dev_str := C.CString(h.Device)
    defer C.free(unsafe.Pointer(dev_str))

    err := C.pcap_setfilter(h.pcap, (*C.struct_bpf_program)(filter.Program()))
    if err < 0 {
        return fmt.Errorf("Could not set filter: %s", h.get_error())
    }

    return nil
}

// Activate the packet source. Note that after calling this method it will not
// be possible to change the packet source configuration (MTU, promiscuous mode,
// monitor mode, ...)
func (h *Handle) Activate() error {
    err := C.pcap_activate(h.pcap)
    if err < 0 {
        return fmt.Errorf("Could not activate: %s", h.get_error())
    }

    return nil
}

// Capture a single packet from the packet source. This will block until a
// packet is received.
func (h *Handle) Capture() ([]byte, error) {
    var buf *C.u_char
    var pkt_hdr *C.struct_pcap_pkthdr

    for {
        err := C.pcap_next_ex(h.pcap, &pkt_hdr, &buf)
        switch err {
        case -2:
            return nil, nil

        case -1:
            return nil, fmt.Errorf(
                "Could not read packet: %s", h.get_error(),
            )

        case 0:
            continue

        case 1:
            return C.GoBytes(unsafe.Pointer(buf),
                             C.int(pkt_hdr.len)), nil
        }
    }

    return nil, fmt.Errorf("WTF")
}

// Inject a packet in the packet source.
func (h *Handle) Inject(buf []byte) error {
    cbuf := (*C.u_char)(&buf[0])
    blen := C.int(len(buf))

    err := C.pcap_sendpacket(h.pcap, cbuf, blen)
    if err < 0 {
        return fmt.Errorf("Could not inject packet: %s", h.get_error())
    }

    return nil
}

// Close the packet source.
func (h *Handle) Close() {
    C.pcap_close(h.pcap)
}

func (h *Handle) get_error() error {
    err_str := C.pcap_geterr(h.pcap)
    return fmt.Errorf(C.GoString(err_str))
}
