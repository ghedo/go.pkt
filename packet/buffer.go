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

package packet

import "encoding/binary"

// A Buffer is a variable-sized buffer of bytes with Read and Write methods.
// It's based on the bytes.Buffer code provided by the standard library, but
// implements additional convenience methods.
//
// This is used internally to provide packet encoding and decoding, and should
// not be used directly.
type Buffer struct {
	buf       []byte
	off       int
	chkoff    int
	bootstrap [64]byte
}

// Initialize the buffer with the given slice.
func (b *Buffer) Init(buf []byte) {
	b.buf = buf
}

// Return the unread portion of the buffer as slice.
func (b *Buffer) Bytes() []byte {
	return b.buf[b.off:]
}

// Return the buffer as slice.
func (b *Buffer) Buffer() []byte {
	return b.buf
}

// Return the number of bytes of the unread portion of the buffer.
func (b *Buffer) Len() int {
	return len(b.buf) - b.off
}

func (b *Buffer) SetOffset(off int) {
	b.off = off
}

// Set the checkpoint to the current buffer offset.
func (b *Buffer) Checkpoint() {
	b.chkoff = len(b.buf) - b.Len()
}

// Return the buffer starting from the last checkpoint, as slice.
func (b *Buffer) BytesOff() []byte {
	return b.buf[b.chkoff:]
}

// Return the number of bytes of the buffer since the last checkpoint.
func (b *Buffer) LenOff() int {
	return len(b.buf) - b.chkoff
}

// Append the contents of p to the buffer, growing the buffer as needed.
func (b *Buffer) Write(p []byte) (n int, err error) {
	if b.Len() < len(p) {
		slice := make([]byte, len(b.buf) + len(p))
		copy(slice, b.buf)
		b.buf = slice
	}

	n = copy(b.buf[b.off:], p)
	b.off += n
	return
}

// Append the binary representation of data in big endian order to the buffer,
// growing the buffer as needed.
func (b *Buffer) WriteI(data interface{}) error {
	return binary.Write(b, binary.BigEndian, data)
}

func (b *Buffer) PutUint16Off(off int, data uint16) {
	binary.BigEndian.PutUint16(b.buf[b.chkoff + off:], data)
}

// Read the next len(p) bytes from the buffer or until the buffer is drained.
func (b *Buffer) Read(p []byte) (n int, err error) {
	n = copy(p, b.buf[b.off:])
	b.off += n
	return
}

// Read structured big endian binary data from r into data.
func (p *Buffer) ReadI(data interface{}) error {
	return binary.Read(p, binary.BigEndian, data)
}

// Return a slice containing the next n bytes from the buffer, advancing the
// buffer as if the bytes had been returned by Read
func (b *Buffer) Next(n int) []byte {
	m := b.Len()
	if n > m {
		n = m
	}
	data := b.buf[b.off : b.off+n]
	b.off += n
	return data
}
