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

package layers_test

import "bytes"
import "log"
import "net"
import "testing"

import "github.com/ghedo/go.pkt/layers"
import "github.com/ghedo/go.pkt/packet"
import "github.com/ghedo/go.pkt/packet/arp"
import "github.com/ghedo/go.pkt/packet/eth"
import "github.com/ghedo/go.pkt/packet/ipv4"
import "github.com/ghedo/go.pkt/packet/raw"
import "github.com/ghedo/go.pkt/packet/udp"
import "github.com/ghedo/go.pkt/packet/tcp"
import "github.com/ghedo/go.pkt/packet/vlan"

var hwsrc_str = "4c:72:b9:54:e5:3d"
var hwdst_str = "00:21:96:6e:f0:70"

var ipsrc_str = "192.168.1.135"
var ipdst_str = "193.27.208.37"

var test_eth_arp = []byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x4c, 0x72, 0xb9, 0x54, 0xe5, 0x3d,
	0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x4c, 0x72,
	0xb9, 0x54, 0xe5, 0x3d, 0xc0, 0xa8, 0x01, 0x87, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xc1, 0x1b, 0xd0, 0x25,
}

func TestPackEthArp(t *testing.T) {
	eth_pkt := eth.Make()
	eth_pkt.SrcAddr, _ = net.ParseMAC(hwsrc_str)
	eth_pkt.DstAddr, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")

	arp_pkt := arp.Make()
	arp_pkt.HWSrcAddr, _ = net.ParseMAC(hwsrc_str)
	arp_pkt.HWDstAddr, _ = net.ParseMAC("00:00:00:00:00:00")
	arp_pkt.ProtoSrcAddr = net.ParseIP(ipsrc_str)
	arp_pkt.ProtoDstAddr = net.ParseIP(ipdst_str)

	buf, err := layers.Pack(eth_pkt, arp_pkt)
	if err != nil {
		t.Fatalf("Error packing: %s", err)
	}

	if !bytes.Equal(test_eth_arp, buf) {
		t.Fatalf("Raw packet mismatch: %x", buf)
	}
}

func TestUnpackEthArp(t *testing.T) {
	_, err := layers.Unpack(test_eth_arp, &eth.Packet{}, &arp.Packet{})
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}
}

func BenchmarkUnpackEthArp(bn *testing.B) {
	var eth_pkt eth.Packet
	var arp_pkt arp.Packet

	for n := 0; n < bn.N; n++ {
		layers.Unpack(test_eth_arp, &eth_pkt, &arp_pkt)
	}
}

func TestUnpackAllEthArp(t *testing.T) {
	pkt, err := layers.UnpackAll(test_eth_arp, packet.Eth)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}

	if pkt.GetType() != packet.Eth {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}

	if pkt.Payload().GetType() != packet.ARP {
		t.Fatalf("Packet type mismatch, %s", pkt.Payload().GetType())
	}
}

func BenchmarkUnpackAllEthArp(bn *testing.B) {
	for n := 0; n < bn.N; n++ {
		layers.UnpackAll(test_eth_arp, packet.Eth)
	}
}

var test_eth_vlan_arp = []byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x4c, 0x72, 0xb9, 0x54, 0xe5, 0x3d,
	0x81, 0x00, 0x00, 0x87, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04,
	0x00, 0x01, 0x4c, 0x72, 0xb9, 0x54, 0xe5, 0x3d, 0xc0, 0xa8, 0x01, 0x87,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc1, 0x1b, 0xd0, 0x25,
}

func TestPackEthVLANArp(t *testing.T) {
	eth_pkt := eth.Make()
	eth_pkt.SrcAddr, _ = net.ParseMAC(hwsrc_str)
	eth_pkt.DstAddr, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")

	vlan_pkt := vlan.Make()
	vlan_pkt.VLAN = 135

	arp_pkt := arp.Make()
	arp_pkt.HWSrcAddr, _ = net.ParseMAC(hwsrc_str)
	arp_pkt.HWDstAddr, _ = net.ParseMAC("00:00:00:00:00:00")
	arp_pkt.ProtoSrcAddr = net.ParseIP(ipsrc_str)
	arp_pkt.ProtoDstAddr = net.ParseIP(ipdst_str)

	buf, err := layers.Pack(eth_pkt, vlan_pkt, arp_pkt)
	if err != nil {
		t.Fatalf("Error packing: %s", err)
	}

	if !bytes.Equal(test_eth_vlan_arp, buf) {
		t.Fatalf("Raw packet mismatch: %x", buf)
	}
}

func TestUnpackEthVLANArp(t *testing.T) {
	_, err := layers.Unpack(test_eth_arp, &eth.Packet{}, &vlan.Packet{}, &arp.Packet{})
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}
}

func BenchmarkUnpackEthVLANArp(bn *testing.B) {
	var eth_pkt eth.Packet
	var vlan_pkt vlan.Packet
	var arp_pkt arp.Packet

	for n := 0; n < bn.N; n++ {
		layers.Unpack(test_eth_vlan_arp, &eth_pkt, &vlan_pkt, &arp_pkt)
	}
}

func TestUnpackAllEthVLANArp(t *testing.T) {
	pkt, err := layers.UnpackAll(test_eth_vlan_arp, packet.Eth)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}

	if pkt.GetType() != packet.Eth {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}

	pkt = pkt.Payload()
	if pkt.GetType() != packet.VLAN {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}

	pkt = pkt.Payload()
	if pkt.GetType() != packet.ARP {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}
}

func BenchmarkUnpackAllEthVLANArp(bn *testing.B) {
	for n := 0; n < bn.N; n++ {
		layers.UnpackAll(test_eth_vlan_arp, packet.Eth)
	}
}

var test_eth_ipv4_udp = []byte{
	0x00, 0x21, 0x96, 0x6e, 0xf0, 0x70, 0x4c, 0x72, 0xb9, 0x54, 0xe5, 0x3d,
	0x08, 0x00, 0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
	0x27, 0x60, 0xc0, 0xa8, 0x01, 0x87, 0xc1, 0x1b, 0xd0, 0x25, 0xa2, 0x5a,
	0x20, 0x92, 0x00, 0x08, 0xe9, 0x80,
}

func TestPackEthIPv4UDP(t *testing.T) {
	eth_pkt := eth.Make()
	eth_pkt.SrcAddr, _ = net.ParseMAC(hwsrc_str)
	eth_pkt.DstAddr, _ = net.ParseMAC(hwdst_str)

	ip4_pkt := ipv4.Make()
	ip4_pkt.SrcAddr = net.ParseIP(ipsrc_str)
	ip4_pkt.DstAddr = net.ParseIP(ipdst_str)

	udp_pkt := udp.Make()
	udp_pkt.SrcPort = 41562
	udp_pkt.DstPort = 8338

	buf, err := layers.Pack(eth_pkt, ip4_pkt, udp_pkt)
	if err != nil {
		t.Fatalf("Error packing: %s", err)
	}

	if !bytes.Equal(test_eth_ipv4_udp, buf) {
		t.Fatalf("Raw packet mismatch: %x", buf)
	}
}

func TestUnpackEthUPv4UDP(t *testing.T) {
	var eth_pkt eth.Packet
	var ip4_pkt ipv4.Packet
	var udp_pkt udp.Packet

	_, err := layers.Unpack(test_eth_ipv4_udp, &eth_pkt, &ip4_pkt, &udp_pkt)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}
}

func BenchmarkUnpackEthUPv4UDP(bn *testing.B) {
	var eth_pkt eth.Packet
	var ip4_pkt ipv4.Packet
	var udp_pkt udp.Packet

	for n := 0; n < bn.N; n++ {
		layers.Unpack(test_eth_ipv4_udp, &eth_pkt, &ip4_pkt, &udp_pkt)
	}
}

func TestUnpackAllEthIPv4UDP(t *testing.T) {
	pkt, err := layers.UnpackAll(test_eth_ipv4_udp, packet.Eth)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}

	if pkt.GetType() != packet.Eth {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}

	pkt = pkt.Payload()
	if pkt.GetType() != packet.IPv4 {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}

	pkt = pkt.Payload()
	if pkt.GetType() != packet.UDP {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}
}

func BenchmarkUnpackAllEthIPv4UDP(bn *testing.B) {
	for n := 0; n < bn.N; n++ {
		layers.UnpackAll(test_eth_ipv4_udp, packet.Eth)
	}
}

var test_eth_ipv4_udp_raw = []byte{
	0x00, 0x21, 0x96, 0x6e, 0xf0, 0x70, 0x4c, 0x72, 0xb9, 0x54, 0xe5, 0x3d,
	0x08, 0x00, 0x45, 0x00, 0x00, 0x42, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
	0x27, 0x3a, 0xc0, 0xa8, 0x01, 0x87, 0xc1, 0x1b, 0xd0, 0x25, 0xa2, 0x5a,
	0x20, 0x92, 0x00, 0x2e, 0x07, 0x03, 0x66, 0x64, 0x67, 0x20, 0x61, 0x67,
	0x66, 0x68, 0x20, 0x6c, 0x64, 0x66, 0x68, 0x67, 0x6b, 0x20, 0x68, 0x66,
	0x64, 0x6b, 0x67, 0x68, 0x20, 0x6b, 0x66, 0x6a, 0x64, 0x68, 0x73, 0x67,
	0x20, 0x6b, 0x73, 0x68, 0x66, 0x64, 0x67, 0x6b,
}

func TestPackEthIPv4UDPRaw(t *testing.T) {
	eth_pkt := eth.Make()
	eth_pkt.SrcAddr, _ = net.ParseMAC(hwsrc_str)
	eth_pkt.DstAddr, _ = net.ParseMAC(hwdst_str)

	ip4_pkt := ipv4.Make()
	ip4_pkt.SrcAddr = net.ParseIP(ipsrc_str)
	ip4_pkt.DstAddr = net.ParseIP(ipdst_str)

	udp_pkt := udp.Make()
	udp_pkt.SrcPort = 41562
	udp_pkt.DstPort = 8338

	raw_pkt := raw.Make()
	raw_pkt.Data = []byte("fdg agfh ldfhgk hfdkgh kfjdhsg kshfdgk")

	data, err := layers.Pack(eth_pkt, ip4_pkt, udp_pkt, raw_pkt)
	if err != nil {
		t.Fatalf("Error packing: %s", err)
	}

	if ip4_pkt.GetLength() != 66 {
		t.Fatalf("IPv4 length mismatch: %d", ip4_pkt.GetLength())
	}

	if udp_pkt.GetLength() != 46 {
		t.Fatalf("UDP length mismatch: %d", udp_pkt.GetLength())
	}

	if !bytes.Equal(test_eth_ipv4_udp_raw, data) {
		t.Fatalf("Raw packet mismatch: %x", data)
	}
}

func TestUnpackEthUPv4UDPRaw(t *testing.T) {
	var eth_pkt eth.Packet
	var ip4_pkt ipv4.Packet
	var udp_pkt udp.Packet
	var raw_pkt raw.Packet

	_, err := layers.Unpack(test_eth_ipv4_udp_raw,
	                        &eth_pkt, &ip4_pkt, &udp_pkt, &raw_pkt)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}
}

func BenchmarkUnpackEthUPv4UDPRaw(bn *testing.B) {
	var eth_pkt eth.Packet
	var ip4_pkt ipv4.Packet
	var udp_pkt udp.Packet
	var raw_pkt raw.Packet

	for n := 0; n < bn.N; n++ {
		layers.Unpack(test_eth_ipv4_udp_raw,
		              &eth_pkt, &ip4_pkt, &udp_pkt, &raw_pkt)
	}
}

func TestUnpackAllEthIPv4UDPRaw(t *testing.T) {
	pkt, err := layers.UnpackAll(test_eth_ipv4_udp_raw, packet.Eth)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}

	if pkt.GetType() != packet.Eth {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}

	pkt = pkt.Payload()
	if pkt.GetType() != packet.IPv4 {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}

	pkt = pkt.Payload()
	if pkt.GetType() != packet.UDP {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}

	pkt = pkt.Payload()
	if pkt.GetType() != packet.Raw {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}
}

func BenchmarkUnpackAllEthIPv4UDPRaw(bn *testing.B) {
	for n := 0; n < bn.N; n++ {
		layers.UnpackAll(test_eth_ipv4_udp_raw, packet.Eth)
	}
}

var test_eth_ipv4_tcp = []byte{
	0x00, 0x21, 0x96, 0x6e, 0xf0, 0x70, 0x4c, 0x72, 0xb9, 0x54, 0xe5, 0x3d,
	0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06,
	0x27, 0x5f, 0xc0, 0xa8, 0x01, 0x87, 0xc1, 0x1b, 0xd0, 0x25, 0xa2, 0x5a,
	0x20, 0x92, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
	0x20, 0x00, 0x79, 0x85, 0x00, 0x00,
}

func TestPackEthIPv4TCP(t *testing.T) {
	eth_pkt := eth.Make()
	eth_pkt.SrcAddr, _ = net.ParseMAC(hwsrc_str)
	eth_pkt.DstAddr, _ = net.ParseMAC(hwdst_str)

	ip4_pkt := ipv4.Make()
	ip4_pkt.SrcAddr = net.ParseIP(ipsrc_str)
	ip4_pkt.DstAddr = net.ParseIP(ipdst_str)

	tcp_pkt := tcp.Make()
	tcp_pkt.SrcPort = 41562
	tcp_pkt.DstPort = 8338
	tcp_pkt.Flags   = tcp.Syn
	tcp_pkt.WindowSize = 8192

	buf, err := layers.Pack(eth_pkt, ip4_pkt, tcp_pkt)
	if err != nil {
		t.Fatalf("Error packing: %s", err)
	}

	if !bytes.Equal(test_eth_ipv4_tcp, buf) {
		t.Fatalf("Raw packet mismatch: %x", buf)
	}
}

func TestUnpackEthUPv4TCP(t *testing.T) {
	var eth_pkt eth.Packet
	var ip4_pkt ipv4.Packet
	var tcp_pkt tcp.Packet

	_, err := layers.Unpack(test_eth_ipv4_tcp, &eth_pkt, &ip4_pkt, &tcp_pkt)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}
}

func BenchmarkUnpackEthUPv4TCP(bn *testing.B) {
	var eth_pkt eth.Packet
	var ip4_pkt ipv4.Packet
	var tcp_pkt tcp.Packet

	for n := 0; n < bn.N; n++ {
		layers.Unpack(test_eth_ipv4_tcp, &eth_pkt, &ip4_pkt, &tcp_pkt)
	}
}

func TestUnpackAllEthIPv4TCP(t *testing.T) {
	pkt, err := layers.UnpackAll(test_eth_ipv4_tcp, packet.Eth)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}

	if pkt.GetType() != packet.Eth {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}

	pkt = pkt.Payload()
	if pkt.GetType() != packet.IPv4 {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}

	pkt = pkt.Payload()
	if pkt.GetType() != packet.TCP {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}
}

func BenchmarkUnpackAllEthIPv4TCP(bn *testing.B) {
	for n := 0; n < bn.N; n++ {
		layers.UnpackAll(test_eth_ipv4_tcp, packet.Eth)
	}
}

var test_eth_ipv4_tcp_raw = []byte{
	0x00, 0x21, 0x96, 0x6e, 0xf0, 0x70, 0x4c, 0x72, 0xb9, 0x54, 0xe5, 0x3d,
	0x08, 0x00, 0x45, 0x00, 0x00, 0x4e, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06,
	0x27, 0x39, 0xc0, 0xa8, 0x01, 0x87, 0xc1, 0x1b, 0xd0, 0x25, 0xa2, 0x5a,
	0x20, 0x92, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
	0x20, 0x00, 0x97, 0x2d, 0x00, 0x00, 0x66, 0x64, 0x67, 0x20, 0x61, 0x67,
	0x66, 0x68, 0x20, 0x6c, 0x64, 0x66, 0x68, 0x67, 0x6b, 0x20, 0x68, 0x66,
	0x64, 0x6b, 0x67, 0x68, 0x20, 0x6b, 0x66, 0x6a, 0x64, 0x68, 0x73, 0x67,
	0x20, 0x6b, 0x73, 0x68, 0x66, 0x64, 0x67, 0x6b,
}

func TestPackEthIPv4TCPRaw(t *testing.T) {
	eth_pkt := eth.Make()
	eth_pkt.SrcAddr, _ = net.ParseMAC(hwsrc_str)
	eth_pkt.DstAddr, _ = net.ParseMAC(hwdst_str)

	ip4_pkt := ipv4.Make()
	ip4_pkt.SrcAddr = net.ParseIP(ipsrc_str)
	ip4_pkt.DstAddr = net.ParseIP(ipdst_str)

	tcp_pkt := tcp.Make()
	tcp_pkt.SrcPort = 41562
	tcp_pkt.DstPort = 8338
	tcp_pkt.Flags   = tcp.Syn
	tcp_pkt.WindowSize = 8192

	raw_pkt := raw.Make()
	raw_pkt.Data = []byte("fdg agfh ldfhgk hfdkgh kfjdhsg kshfdgk")

	data, err := layers.Pack(eth_pkt, ip4_pkt, tcp_pkt, raw_pkt)
	if err != nil {
		t.Fatalf("Error packing: %s", err)
	}

	if ip4_pkt.GetLength() != 78 {
		t.Fatalf("IPv4 length mismatch: %d", ip4_pkt.GetLength())
	}

	if tcp_pkt.GetLength() != 58 {
		t.Fatalf("TCP length mismatch: %d", tcp_pkt.GetLength())
	}

	if !bytes.Equal(test_eth_ipv4_tcp_raw, data) {
		t.Fatalf("Raw packet mismatch: %x", data)
	}
}

func TestUnpackEthUPv4TCPRaw(t *testing.T) {
	var eth_pkt eth.Packet
	var ip4_pkt ipv4.Packet
	var tcp_pkt tcp.Packet
	var raw_pkt raw.Packet

	_, err := layers.Unpack(test_eth_ipv4_tcp_raw,
	                        &eth_pkt, &ip4_pkt, &tcp_pkt, &raw_pkt)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}
}

func BenchmarkUnpackEthUPv4TCPRaw(bn *testing.B) {
	var eth_pkt eth.Packet
	var ip4_pkt ipv4.Packet
	var tcp_pkt tcp.Packet
	var raw_pkt raw.Packet

	for n := 0; n < bn.N; n++ {
		layers.Unpack(test_eth_ipv4_tcp_raw,
		              &eth_pkt, &ip4_pkt, &tcp_pkt, &raw_pkt)
	}
}

func TestUnpackAllEthIPv4TCPRaw(t *testing.T) {
	pkt, err := layers.UnpackAll(test_eth_ipv4_tcp_raw, packet.Eth)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}

	if pkt.GetType() != packet.Eth {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}

	pkt = pkt.Payload()
	if pkt.GetType() != packet.IPv4 {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}

	pkt = pkt.Payload()
	if pkt.GetType() != packet.TCP {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}

	pkt = pkt.Payload()
	if pkt.GetType() != packet.Raw {
		t.Fatalf("Packet type mismatch, %s", pkt.GetType())
	}
}

func BenchmarkUnpackAllEthIPv4TCPRaw(bn *testing.B) {
	for n := 0; n < bn.N; n++ {
		layers.UnpackAll(test_eth_ipv4_tcp_raw, packet.Eth)
	}
}

func TestFindLayer(t *testing.T) {
	pkt, err := layers.UnpackAll(test_eth_ipv4_tcp, packet.Eth)
	if err != nil {
		t.Fatalf("Error unpacking: %s", err)
	}

	ipv4_pkt := layers.FindLayer(pkt, packet.IPv4)
	if ipv4_pkt == nil || ipv4_pkt.GetType() != packet.IPv4 {
		t.Fatalf("Not IPv4: %s", ipv4_pkt)
	}

	tcp_pkt := layers.FindLayer(pkt, packet.TCP)
	if tcp_pkt == nil || tcp_pkt.GetType() != packet.TCP {
		t.Fatalf("Not TCP: %s", tcp_pkt)
	}

	udp_pkt := layers.FindLayer(pkt, packet.UDP)
	if udp_pkt != nil {
		t.Fatalf("Not nil: %s", udp_pkt)
	}
}

func ExamplePack() {
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
}

func ExampleUnpack() {
	// Create the buf data
	buf := []byte("random data")

	// Assume Ethernet as datalink layer
	pkt, err := layers.UnpackAll(buf, packet.Eth)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(pkt)
}
