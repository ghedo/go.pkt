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
    layer_off int
}

// Initialize the buffer with the given slice.
func (b *Buffer) Init(buf []byte) {
    b.buf = buf
    b.off = 0
    b.layer_off = 0
}

// Return the unread portion of the buffer as slice.
func (b *Buffer) Bytes() []byte {
    return b.buf[b.off:]
}

// Return the whole buffer as slice.
func (b *Buffer) Buffer() []byte {
    return b.buf
}

// Return the number of bytes of the unread portion of the buffer.
func (b *Buffer) Len() int {
    return len(b.buf) - b.off
}

// Manually set the buffer offset to off.
func (b *Buffer) SetOffset(off int) {
    b.off = off
}

// Point the layer starting offset to the current buffer offset.
func (b *Buffer) NewLayer() {
    b.layer_off = len(b.buf) - b.Len()
}

// Return the buffer of the current layer as slice.
func (b *Buffer) LayerBytes() []byte {
    return b.buf[b.layer_off:]
}

// Return the length of the current decoded layer.
func (b *Buffer) LayerLen() int {
    return b.off - b.layer_off
}

// Append the contents of p to the buffer.
func (b *Buffer) Write(p []byte) (n int, err error) {
    n = copy(b.buf[b.off:], p)
    b.off += n
    return
}

// Append the value of data to the buffer in network byter order.
func (b *Buffer) WriteN(data interface{}) error {
    return binary.Write(b, binary.BigEndian, data)
}

// Append the value of data to the buffer in little endian byter order.
func (b *Buffer) WriteL(data interface{}) error {
    return binary.Write(b, binary.LittleEndian, data)
}

// Write data in network byte order to the specified offset relative to the
// start of the current layer.
func (b *Buffer) PutUint16N(off int, data uint16) {
    binary.BigEndian.PutUint16(b.buf[b.layer_off + off:], data)
}

// Read the next len(p) bytes from the buffer or until the buffer is drained.
func (b *Buffer) Read(p []byte) (n int, err error) {
    n = copy(p, b.buf[b.off:])
    b.off += n
    return
}

// Read structured data from the buffer in network byte order.
func (p *Buffer) ReadN(data interface{}) error {
    return binary.Read(p, binary.BigEndian, data)
}

// Read structured data from the buffer in little endian byte order.
func (p *Buffer) ReadL(data interface{}) error {
    return binary.Read(p, binary.LittleEndian, data)
}

// Read aligned structured data from the buffer in little endian byte order.
func (p *Buffer) ReadLAligned(data interface{}, width uintptr) error {
    p.off = ((((p.off) + ((int(width)) - 1)) & (^((int(width)) - 1))) - p.off)

    return binary.Read(p, binary.LittleEndian, data)
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
