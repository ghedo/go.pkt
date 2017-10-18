package main

import "log"
import "net"
import "strconv"

import "github.com/docopt/docopt-go"

import "github.com/songgao/water"

import "github.com/ghedo/go.pkt/packet"
import "github.com/ghedo/go.pkt/packet/ipv6"
import "github.com/ghedo/go.pkt/packet/icmpv6"
import "github.com/ghedo/go.pkt/packet/tcp"
import "github.com/ghedo/go.pkt/packet/udp"
import "github.com/ghedo/go.pkt/layers"

func main() {
    log.SetFlags(0)

    usage := `Usage: tracereply <netif> <hops> <start_addr>

Reply to ICMPv6 traceroutes.`

    args, err := docopt.Parse(usage, nil, true, "", false)
    if err != nil {
        log.Fatalf("Invalid arguments: %s", err)
    }

    netif := args["<netif>"].(string)
    ip    := net.ParseIP(args["<start_addr>"].(string))

    hops, err := strconv.ParseUint(args["<hops>"].(string), 10, 8)
    if err != nil {
        log.Fatalf("Error parsing hop paramenter: %s", err)
    }

    config := water.Config{ DeviceType: water.TUN }
    config.Name = netif

    capture, err := water.New(config)
    if err != nil {
        log.Fatalf("Error creating capture interface: %s", err)
    }

    for {
        buf := make([]byte, 1500)

        buf_len, err := capture.Read(buf)
        if err != nil {
            log.Fatalf("Error reading packet from interface: %s", err)
        }

        buf = buf[:buf_len]

        pkt, err := layers.UnpackAll(buf, packet.IPv6)
        if err != nil {
            log.Printf("Error unpacking packet: %s", err)
            continue;
        }

        ip_pkt := layers.FindLayer(pkt, packet.IPv6)
        if ip_pkt == nil {
            continue;
        }

        if ip_pkt.Payload() == nil {
            continue
        }

        reply_ip_pkt := ipv6.Make()
        reply_ip_pkt.DstAddr = ip_pkt.(*ipv6.Packet).SrcAddr

        ttl := ip_pkt.(*ipv6.Packet).HopLimit

        reply_pkts := []packet.Packet{ reply_ip_pkt }

        switch {
        case uint64(ttl) < hops:
            []byte(ip)[len(ip) - 1] = ttl

            reply_ip_pkt.SrcAddr = ip

            reply_pkt := icmpv6.Make()

            reply_pkt.Type = icmpv6.TimeExceeded
            reply_pkt.Code = 0

            reply_pkts = append(reply_pkts, reply_pkt, ip_pkt, ip_pkt.Payload())

        case uint64(ttl) >= hops:
            reply_ip_pkt.SrcAddr = ip_pkt.(*ipv6.Packet).DstAddr

            switch ip_pkt.Payload().GetType() {
            case packet.ICMPv6:
                reply_pkt := icmpv6.Make()

                reply_pkt.Type = icmpv6.EchoReply
                reply_pkt.Code = 0
                reply_pkt.Body = ip_pkt.Payload().(*icmpv6.Packet).Body

                reply_pkts = append(reply_pkts, reply_pkt)

            case packet.TCP:
                reply_pkt := tcp.Make()

                reply_pkt.SrcPort = ip_pkt.Payload().(*tcp.Packet).DstPort
                reply_pkt.DstPort = ip_pkt.Payload().(*tcp.Packet).SrcPort
                reply_pkt.Flags   = tcp.Rst

                reply_pkts = append(reply_pkts, reply_pkt)

            case packet.UDP:
                reply_pkt := udp.Make()

                reply_pkt.SrcPort = ip_pkt.Payload().(*udp.Packet).DstPort
                reply_pkt.DstPort = ip_pkt.Payload().(*udp.Packet).SrcPort

                reply_pkts = append(reply_pkts, reply_pkt,
                                    ip_pkt.Payload().Payload())
            }
        }

        reply_buf, err := layers.Pack(reply_pkts...)
        if err != nil {
            log.Printf("Error while packing: %s\n", err)
            continue;
        }

        capture.Write(reply_buf)
    }
}
