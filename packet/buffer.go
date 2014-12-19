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
import "io"

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

// Return the buffer as slice.
func (b *Buffer) Bytes() []byte {
	return b.buf[b.off:]
}

// Return the number of bytes of the unread portion of the buffer.
func (b *Buffer) Len() int {
	return len(b.buf) - b.off
}

// Set the checkpoint to the current buffer offset.
func (b *Buffer) Checkpoint() {
	b.chkoff = b.Len()
}

// Return the buffer starting from the last checkpoint, as slice.
func (b *Buffer) BytesOff() []byte {
	return b.buf[b.chkoff:]
}

// Return the number of bytes of the buffer since the last checkpoint.
func (b *Buffer) LenOff() int {
	return len(b.buf) - b.chkoff
}

// Discard all but the first n unread bytes from the buffer.
func (b *Buffer) Truncate(n int) {
	switch {
	case n < 0 || n > b.Len():
		panic("OOR")

	case n == 0:
		b.off = 0
	}

	b.buf = b.buf[0 : b.off+n]
}

func (b *Buffer) grow(n int) int {
	m := b.Len()

	if m == 0 && b.off != 0 {
		b.Truncate(0)
	}

	if len(b.buf)+n > cap(b.buf) {
		var buf []byte

		if b.buf == nil && n <= len(b.bootstrap) {
			buf = b.bootstrap[0:]
		} else if m+n <= cap(b.buf) / 2 {
			copy(b.buf[:], b.buf[b.off:])
			buf = b.buf[:m]
		} else {
			// not enough space anywhere
			buf = makeSlice(2 * cap(b.buf) + n)
			copy(buf, b.buf[b.off:])
		}

		b.buf = buf
		b.off = 0
	}

	b.buf = b.buf[0 : b.off + m + n]

	return b.off + m
}

// Append the contents of p to the buffer, growing the buffer as needed.
func (b *Buffer) Write(p []byte) (n int, err error) {
	m := b.grow(len(p))
	return copy(b.buf[m:], p), nil
}

// Append the binary representation of data in big endian order to the buffer,
// growing the buffer as needed.
func (b *Buffer) WriteI(data interface{}) error {
	return binary.Write(b, binary.BigEndian, data)
}

func (b *Buffer) PutUint16Off(off int, data uint16) {
	binary.BigEndian.PutUint16(b.buf[b.chkoff + off:], data)
}

func makeSlice(n int) []byte {
	defer func() {
		if recover() != nil {
			panic("OOM")
		}
	}()
	return make([]byte, n)
}

// Read the next len(p) bytes from the buffer or until the buffer is drained.
func (b *Buffer) Read(p []byte) (n int, err error) {
	if b.off >= len(b.buf) {
		b.Truncate(0)
		if len(p) == 0 {
			return
		}
		return 0, io.EOF
	}
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
