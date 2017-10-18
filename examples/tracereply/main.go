package main

import "log"
import "net"
import "strconv"

import "github.com/docopt/docopt-go"

import "github.com/songgao/water"

import "github.com/ghedo/go.pkt/packet"
import "github.com/ghedo/go.pkt/packet/ipv6"
import "github.com/ghedo/go.pkt/packet/icmpv6"
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

    capture, err := water.NewTUN(netif)
    if err != nil {
        log.Fatalf("Error creating capture interface: %s", err)
    }

    log.Println(ip)

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
            continue;
        }

        icmp_pkt := layers.FindLayer(pkt, packet.ICMPv6)
        if ip_pkt == nil {
            continue;
        }

        if icmp_pkt.(*icmpv6.Packet).Type != icmpv6.EchoRequest {
            continue;
        }

        reply_ip_pkt := ipv6.Make()
        reply_ip_pkt.DstAddr = ip_pkt.(*ipv6.Packet).SrcAddr

        reply_icmp_pkt := icmpv6.Make()

        ttl := ip_pkt.(*ipv6.Packet).HopLimit

        switch {
        case uint64(ttl) < hops:
            []byte(ip)[len(ip) - 1] = ttl

            reply_ip_pkt.SrcAddr = ip

            reply_icmp_pkt.Type = icmpv6.TimeExceeded
            reply_icmp_pkt.Code = 0

            reply_buf, err := layers.Pack(reply_ip_pkt, reply_icmp_pkt,
                                                ip_pkt,       icmp_pkt)
            if err != nil {
                log.Printf("Error while packing: %s\n", err)
                continue;
            }

            capture.Write(reply_buf)

        case uint64(ttl) >= hops:
            reply_ip_pkt.SrcAddr = ip_pkt.(*ipv6.Packet).DstAddr

            reply_icmp_pkt.Type = icmpv6.EchoReply
            reply_icmp_pkt.Code = 0
            reply_icmp_pkt.Body = icmp_pkt.(*icmpv6.Packet).Body

            reply_buf, err := layers.Pack(reply_ip_pkt, reply_icmp_pkt)
            if err != nil {
                log.Printf("Error while packing: %s\n", err)
                continue;
            }

            capture.Write(reply_buf)
        }
    }
}
