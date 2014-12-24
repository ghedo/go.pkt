hype
====

![Travis CI](https://secure.travis-ci.org/ghedo/hype.png)

**hype** provides Go libraries for capturing, injecting, filtering, encoding and
decoding network packets.

* [capture] [capture]: provides the basic interface for packet capturing and
  injection. Different implementations ("pcap", "file", ...) are provided as
  subpackages.

* [filter] [filter]: provides an API for compiling and manipulating BPF filters.
  A filter can be either compiled from tcpdump-like expressions, or created from
  basic BPF instructions. Filters can then be either applied to packet sources
  (see the capture package) or directly run against binary data.

* [packet] [packet]: provides the interfaces for implementing packet encoders
  and decoders. Every supported protocol implements the Packet interface as a
  submodule of this package (e.g. packet/ipv4, packet/tcp, ...).

* [layers] [layers]: provides utility functions for encoding and decoding
  packets to/from binary data. Differently from the basic "packet" interface,
  this can encode and decode complete "stacks" of packets, instead of
  manipulating single ones.

* [network] [network]: provides utility functions for sending and receiving
  packets over the network. Basically, it hides some of the complexity of using
  the capture and layers packages together.

* [routing] [routing]: provides network routing information about the system. It
  can either return all available routes or select a specific route depending on
  a destination address.

[capture]: http://godoc.org/github.com/ghedo/hype/capture
[filter]: http://godoc.org/github.com/ghedo/hype/filter
[packet]: http://godoc.org/github.com/ghedo/hype/packet
[layers]: http://godoc.org/github.com/ghedo/hype/layers
[network]: http://godoc.org/github.com/ghedo/hype/network
[routing]: http://godoc.org/github.com/ghedo/hype/routing

## GETTING STARTED

### Capturing

Packet capturing is done using a packet "source" such as a network interface or
a dump file.

In the following example we create a "pcap" capture handle using the `eth0`
network interface, we activate it and then capture packets using the `Capture()`
method.

```go
src, err := pcap.Open("eth0")
if err != nil {
	log.Fatal(err)
}
defer src.Close()

// you may configure the source further, e.g. by activating
// promiscuous mode.

err = src.Activate()
if err != nil {
	log.Fatal(err)
}

for {
	buf, err := src.Capture()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("PACKET!!!")

	// do something with the packet
}
```

### Injection

Similarly to packet capturing, packet injection requires a capture handle.

In the following example we create a capture handle like before and then use
the `Inject()` method to send some data (we'll see later how to encode data in
the propert formats).

```go
dst, err := pcap.Open("eth0")
if err != nil {
	log.Fatal(err)
}
defer dst.Close()

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
```

### Filtering

Packet filtering is done by creating a filter (e.g. by compiling it from an
expression) which can be either applied to a capture handle (by using the
`ApplyFilter()` method) or used directly against a data buffer.

In the following example we create a filter by compiling a tcpdump-like
expression and then try to match some data against it.

```go
// Match UDP or TCP packets on top of Ethernet
flt, err := filter.Compile("udp or tcp", packet.Eth)
if err != nil {
	log.Fatal(err)
}

if flt.Match([]byte("random data")) {
	log.Println("MATCH!!!")
}
```

### Encoding

Encoding packets is done by using the functions provided by the `layers`
package.

In the following example we create an ARP packet on top of an Ethernet packet
and we encode them to binary data by using the `Pack()` method. Note that you'll
need to import the packages of the protocols used (`packet/eth` and `packet/arp`).

```go
// Create an Ethernet packet
eth_pkt := eth.Make()
eth_pkt.SrcAddr, _ = net.ParseMAC("4c:72:b9:54:e5:3d")
eth_pkt.DstAddr, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")

// Create an ARP packet
arp_pkt := arp.Make()
arp_pkt.HWSrcAddr, _ = net.ParseMAC("4c:72:b9:54:e5:3d")
arp_pkt.HWDstAddr, _ = net.ParseMAC("00:00:00:00:00:00")
arp_pkt.ProtoSrcAddr = net.ParseIP("192.168.1.135")
arp_pkt.ProtoDstAddr = net.ParseIP("192.168.1.254")

buf, err := layers.Pack(eth_pkt, arp_pkt)
if err != nil {
	log.Fatal(err)
}

// do something with the packet
log.Println(buf)
```

### Decoding

Like encoding, decoding is done by using the functions provided by the `layers`
package.

The following example uses the `UnpackAll()` function to decode a whole chain of
packets (e.g. ethernet -> ipv4 -> udp).

```go
// Create the buf data
buf := []byte("random data")

// Assume Ethernet as datalink layer
pkt, err := layers.UnpackAll(buf, packet.Eth)
if err != nil {
	log.Fatal(err)
}

log.Println(pkt)
```

### Network

Instead of using the layers and capture packages together, the network package
can be used instead.

The following example creates an ARP request packet and uses `SendRecv()` to
send it and receive a suitable answer.

```go
c, err := pcap.Open("eth0")
if err != nil {
	log.Fatal(err)
}
defer c.Close()

err = c.Activate()
if err != nil {
	log.Fatal(err)
}

// Create an Ethernet packet
eth_pkt := eth.Make()
eth_pkt.SrcAddr, _ = net.ParseMAC("4c:72:b9:54:e5:3d")
eth_pkt.DstAddr, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")

// Create an ARP packet
arp_pkt := arp.Make()
arp_pkt.HWSrcAddr, _ = net.ParseMAC("4c:72:b9:54:e5:3d")
arp_pkt.HWDstAddr, _ = net.ParseMAC("00:00:00:00:00:00")
arp_pkt.ProtoSrcAddr = net.ParseIP("192.168.1.135")
arp_pkt.ProtoDstAddr = net.ParseIP("192.168.1.254")

rsp_pkt, err := network.SendRecv(c, 0, eth_pkt, arp_pkt)
if err != nil {
	log.Fatal(err)
}

log.Println(rsp_pkt)
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
