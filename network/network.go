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

// Provides utility functions for sending and receiving packets over the
// network. Basically, it hides some of the complexity of using the capture and
// layers packages together.
package network

import "fmt"
import "time"

import "github.com/ghedo/go.pkt/capture"
import "github.com/ghedo/go.pkt/packet"
import "github.com/ghedo/go.pkt/layers"

// Pack packets into their binary form and inject them in the given capture
// handle.. This will stack the packets before encoding them and also calculate
// the checksums.
func Send(c capture.Handle, pkts ...packet.Packet) error {
	if pkts[0].GetType() != c.LinkType() {
		return fmt.Errorf("Expected packet type %s, got %s",
		                  pkts[0].GetType(), c.LinkType())
	}

	buf, err := layers.Pack(pkts...)
	if err != nil {
		return fmt.Errorf("Could not pack: %s", err)
	}

	err = c.Inject(buf)
	if err != nil {
		return fmt.Errorf("Could not inject: %s", err)
	}

	return nil
}

// Capture a single packet from the given capture handle, unpack it and return
// it. This will block until a packet is received.
func Recv(c capture.Handle) (packet.Packet, error) {
	buf, err := c.Capture()
	if err != nil {
		return nil, fmt.Errorf("Could not capture: %s", err)
	}

	pkt, err := layers.UnpackAll(buf, c.LinkType())
	if err != nil {
		return nil, fmt.Errorf("Could not unpack: %s", err)
	}

	return pkt, nil
}

// Like Send() and Recv() combined. This only returns a suitable answer for the
// sent packets. If t is not zero, this will return if not answer is received
// before t expires.
func SendRecv(c capture.Handle, t time.Duration, pkts ...packet.Packet) (packet.Packet, error) {
	err := Send(c, pkts...)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	for {
		pkt, err := Recv(c)
		if err != nil {
			return nil, err
		}

		if pkt == nil {
			return nil, nil
		}

		if pkt.Answers(pkts[0]) {
			return pkt, nil
		}

		if int64(t) > 0 &&
		   int64(time.Since(now)) > int64(t.Nanoseconds()) {
			return nil, fmt.Errorf("Timeout")
		}
	}

	return nil, fmt.Errorf("WTF")
}
