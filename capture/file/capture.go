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

// Provides native packet capturing and injection on pcap dump files without
// requiring the libpcap library.
package file

import "bytes"
import "encoding/binary"
import "fmt"
import "io"
import "os"

import "github.com/ghedo/hype/filter"
import "github.com/ghedo/hype/packet"

type Handle struct {
	File  string
	file   *os.File
	out    *os.File
	order  binary.ByteOrder
	link   uint32
	mtu    uint32
	filter *filter.Filter
}

var BigEndian    = []byte{0xa1, 0xb2, 0xc3, 0xd4}
var LittleEndian = []byte{0xd4, 0xc3, 0xb2, 0xa1}

// Create a new capture handle from the given dump file. This will either open
// the file if it exists, or create a new one.
func Open(file_name string) (*Handle, error) {
	handle := &Handle{ File: file_name }

	open := open_file

	if _, err := os.Stat(file_name); os.IsNotExist(err) {
		open = create_file
	}

	file, err := open(file_name)
	if err != nil {
		return nil, err
	}

	handle.file = file

	handle.file.Seek(0, 0)

	magic := make([]byte, 4)
	file.Read(magic)

	switch {
	case bytes.Equal(magic, BigEndian):
		handle.order = binary.BigEndian

	case bytes.Equal(magic, LittleEndian):
		handle.order = binary.LittleEndian

	default:
		handle.file.Close()
		return nil, fmt.Errorf("Invalid file")
	}

	var ver_maj, ver_min uint16
	var discard, mtu, link_type uint32

	binary.Read(file, handle.order, &ver_maj)
	binary.Read(file, handle.order, &ver_min)
	binary.Read(file, handle.order, &discard)
	binary.Read(file, handle.order, &discard)
	binary.Read(file, handle.order, &mtu)
	binary.Read(file, handle.order, &link_type)

	handle.link = link_type
	handle.mtu  = mtu

	/*
	 * Use a different file handle for injecting packages so that we don't
	 * need to seek back and forth for capturing and injecting
	 */
	handle.out, _ = open_file(file_name)
	handle.out.Seek(0, 2)

	return handle, nil
}

func create_file(file_name string) (*os.File, error) {
	file, err := os.Create(file_name)
	if err != nil {
		return nil, fmt.Errorf("Could not create file: %s", err)
	}

	file.Write(BigEndian) /* endiannes */

	binary.Write(file, binary.BigEndian, uint16(2)) /* ver major */
	binary.Write(file, binary.BigEndian, uint16(4)) /* ver minor */
	binary.Write(file, binary.BigEndian, uint32(0))
	binary.Write(file, binary.BigEndian, uint32(0))
	binary.Write(file, binary.BigEndian, uint32(0x7fff)) /* MTU */
	binary.Write(file, binary.BigEndian, uint32(1)) /* link type */

	return file, nil
}

func open_file(file_name string) (*os.File, error) {
	file, err := os.OpenFile(file_name, os.O_RDWR, 0644);
	if err != nil {
		return nil, fmt.Errorf("Could not open file: %s", err)
	}

	return file, nil
}

// Return the link type of the capture handle (that is, the type of packets that
// come out of the packet source).
func (h *Handle) LinkType() packet.Type {
	return packet.LinkType(h.link)
}

// Not supported.
func (h *Handle) SetMTU(mtu int) error {
	return fmt.Errorf("Unsupported")
}

// Not supported.
func (h *Handle) SetPromiscMode(promisc bool) error {
	return fmt.Errorf("Unsupported")
}

// Not supported.
func (h *Handle) SetMonitorMode(monitor bool) error {
	return fmt.Errorf("Unsupported")
}

// Apply the given filter it to the packet source. Only packets that match this
// filter will be captured.
func (h *Handle) ApplyFilter(filter *filter.Filter) error {
	if !filter.Validate() {
		return fmt.Errorf("Invalid filter")
	}

	h.filter = filter
	return nil
}

// Activate the capture handle (this is not needed for the file capture handle,
// but you may want to call it anyway in order to make switching to different
// packet sources easier).
func (h *Handle) Activate() error {
	return nil
}

// Capture a single packet from the packet source. If no packet is available
// (i.e. if the end of the dump file has been reached) it will return a nil
// slice.
func (h *Handle) Capture() ([]byte, error) {
	var raw_pkt []byte
	var sec, usec, caplen, wirelen uint32

	for {
		binary.Read(h.file, h.order, &sec)
		binary.Read(h.file, h.order, &usec)
		binary.Read(h.file, h.order, &caplen)
		binary.Read(h.file, h.order, &wirelen)

		if caplen == 0 {
			return nil, nil
		}

		raw_pkt = make([]byte, int(caplen))

		_, err := h.file.Read(raw_pkt)
		if err == io.EOF {
			return nil, nil
		}

		if err != nil  {
			return nil, fmt.Errorf("Could not capture: %s", err)
		}

		if h.filter != nil && !h.filter.Match(raw_pkt) {
			continue
		}

		break
	}

	return raw_pkt, nil
}

// Inject a packet in the packet source. This will automatically append packets
// at the end of the dump file, instead of truncating it.
func (h *Handle) Inject(raw_pkt []byte) error {
	var sec, usec, caplen, wirelen uint32

	sec     = 0
	usec    = 0
	caplen  = uint32(len(raw_pkt))
	wirelen = caplen

	binary.Write(h.out, h.order, sec)
	binary.Write(h.out, h.order, usec)
	binary.Write(h.out, h.order, caplen)
	binary.Write(h.out, h.order, wirelen)

	n, err := h.out.Write(raw_pkt)
	if err != nil || n < len(raw_pkt) {
		return fmt.Errorf("Could not write packet: %s", err)
	}

	return nil
}

// Close the packet source.
func (h *Handle) Close() {
	h.file.Close()
	h.out.Close()
}
