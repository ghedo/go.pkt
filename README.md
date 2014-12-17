hype
====

![Travis CI](https://secure.travis-ci.org/ghedo/hype.png)

**hype** provides Go libraries for capturing, injecting, filtering, encoding and
decoding network packets.

* [hype/capture](http://godoc.org/github.com/ghedo/hype/capture): provides
  packet capture and injection functionality using different kind of packet
  sources (e.g. live network interfaces via libpcap, pcap dump files, ...). All
  capture sources implement a common interface to make switching between them
  easier. Note however that not all sources support all the available features
  (e.g. you can't put a dump file into promiscuous mode).

* [hyper/filter](http://godoc.org/github.com/ghedo/hype/filter): provides packet
  filtering capabilities by generating BPF filters based on input rules. Note
  that currently it uses the pcap filter compiler, but the plan is to also
  support compiling custom BPF programs in the future.

* [hype/packet](http://godoc.org/github.com/ghedo/hype/packet): provides packet
  encoding and decoding capabilities. Every supported protocol provides its own
  submodule that implements the same common interface. Additionally the
  [hype/packet/util](http://godoc.org/github.com/ghedo/hype/packet/util) module
  provides additional convenience functions for manipulating packets (e.g.
  encoding or decoding chains of packages).

* [hype/routing](http://godoc.org/github.com/ghedo/hype/packet): provides
  routing information on the host system. It can either return all available
  routes or select a specific route depending on the destination address.

## GETTING STARTED

### Capturing

Packet capturing is done using a packet "source" such as a network interface or
a dump file.

In the following example we create a "live" capture handle using the `eth0`
network interface, we activate it and then capture packets using the `Capture()`
method.

```go
package main

import "log"

import "github.com/ghedo/hype/capture/live"

func main() {
	src, err := live.Open("eth0")
	if err != nil {
		log.Fatal(err)
	}

	// you may configure the source further, e.g. by activating
	// promiscuous mode.

	err = src.Activate()
	if err != nil {
		log.Fatal(err)
	}

	for {
		raw_pkt, err := src.Capture()
		if err != nil {
			log.Fatal(err)
		}

		if raw_pkt == nil {
			break
		}

		log.Println("PACKET!!!")

		// do something with the packet
	}
}
```

### Injection

Similarly to packet capturing, packet injection requires a capture handle.

In the following example we create a capture handle like before and then use
the `Inject()` method to send some data (we'll see later how to encode data in
the propert formats).

```go
package main

import "log"

import "github.com/ghedo/hype/capture/live"

func main() {
	dst, err := live.Open("eth0")
	if err != nil {
		log.Fatal(err)
	}

	// you may configure the source further, e.g. by activating
	// promiscuous mode.

	err = dst.Activate()
	if err != nil {
		log.Fatal(err)
	}

	err = dst.Inject([]byte("random data"))
	if err != nil {
		log.Fatal(err)
	}
}
```

### Filtering

TODO

### Encoding

Encoding packets is done by using the functions provided by the `util` package.

In the following example we create an ARP packet on top of an Ethernet packet
and we encode them to binary data by using the `Pack()` method.

```go
package main

import "log"
import "net"

import "github.com/ghedo/hype/packet/eth"
import "github.com/ghedo/hype/packet/arp"
import "github.com/ghedo/hype/packet/util"

func main() {
	eth_pkt := eth.Make()
	eth_pkt.SrcAddr, _ = net.ParseMAC("4c:72:b9:54:e5:3d")
	eth_pkt.DstAddr, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")

	arp_pkt := arp.Make()
	arp_pkt.HWSrcAddr, _ = net.ParseMAC("4c:72:b9:54:e5:3d")
	arp_pkt.HWDstAddr, _ = net.ParseMAC("00:00:00:00:00:00")
	arp_pkt.ProtoSrcAddr = net.ParseIP("192.168.1.135")
	arp_pkt.ProtoDstAddr = net.ParseIP("192.168.1.254")

	raw_pkt, err := util.Pack(eth_pkt, arp_pkt)
	if err != nil {
		log.Fatal(err)
	}

	// do something with the packet
}
```

### Decoding

Like encoding, decoding is done by using the functions provided by the `util`
package.

The following example uses the `UnpackAll()` function to decode a whole chain of
packets (e.g. ethernet -> ipv4 -> udp), and returns a slice containing the
decoded packets.

```go
package main

import "log"

import "github.com/ghedo/hype/packet"
import "github.com/ghedo/hype/packet/util"

func main() {
	// create the raw_pkt data

	pkts, err := util.UnpackAll(raw_pkt, packet.Eth)
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range pkts {
		log.Println(p)
	}
}
```

### Routing

TODO

For more examples have a look at the [examples](examples/) directory in the
source repository.

## DEPENDENCIES

 * `libpcap`

## COPYRIGHT

Copyright (C) 2014 Alessandro Ghedini <alessandro@ghedini.me>

See COPYING for the license.
