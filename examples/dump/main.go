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

package main

import "log"
import "strconv"

import "github.com/docopt/docopt-go"

import "github.com/ghedo/go.pkt/capture"
import "github.com/ghedo/go.pkt/capture/pcap"
import "github.com/ghedo/go.pkt/capture/file"
import "github.com/ghedo/go.pkt/filter"
import "github.com/ghedo/go.pkt/layers"

func main() {
	log.SetFlags(0)

	usage := `Usage: dump [options] [<expression>]

Dump the traffic on the network (like tcpdump).

Options:
  -c <count>  Exit after receiving count packets.
  -i <iface>  Listen on interface.
  -r <file>   Read packets from file.
  -w <file>   Write the raw packets to file.`

	args, err := docopt.Parse(usage, nil, true, "", false)
	if err != nil {
		log.Fatalf("Invalid arguments: %s", err)
	}

	var count uint64

	if args["-c"] != nil {
		count, err = strconv.ParseUint(args["-c"].(string), 10, 64)
		if err != nil {
			log.Fatalf("Error parsing count: %s", err)
		}
	}

	var src capture.Handle

	if args["-i"] != nil {
		src, err = pcap.Open(args["-i"].(string))
		if err != nil {
			log.Fatalf("Error opening iface: %s", err)
		}
	} else if args["-r"] != nil {
		src, err = file.Open(args["-r"].(string))
		if err != nil {
			log.Fatalf("Error opening file: %s", err)
		}
	} else {
		log.Fatalf("Must select a source (either -i or -r)")
	}
	defer src.Close()

	var dst capture.Handle

	if args["-w"] != nil {
		dst, err = file.Open(args["-w"].(string))
		if err != nil {
			log.Fatalf("Error opening file: %s", err)
		}
		defer dst.Close()
	}

	err = src.Activate()
	if err != nil {
		log.Fatalf("Error activating source: %s", err)
	}

	if args["<expression>"] != nil {
		expr := args["<expression>"].(string)

		flt, err := filter.Compile(expr, src.LinkType(), false)
		if err != nil {
			log.Fatalf("Error parsing filter: %s", err)
		}
		defer flt.Cleanup()

		err = src.ApplyFilter(flt)
		if err != nil {
			log.Fatalf("Error appying filter: %s", err)
		}
	}

	var i uint64

	for {
		buf, err := src.Capture()
		if err != nil {
			log.Fatalf("Error: %s", err)
			break
		}

		if buf == nil {
			break
		}

		i++

		if dst == nil {
			rcv_pkt, err := layers.UnpackAll(buf, src.LinkType())
			if err != nil {
				log.Printf("Error: %s\n", err)
			}

			log.Println(rcv_pkt)
		} else {
			dst.Inject(buf)
		}

		if count > 0 && i >= count {
			break
		}
	}
}
