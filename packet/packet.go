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

// Provides the interfaces for implementing packet encoders and decoders. Every
// supported protocol implements the Packet interface as a submodule of this
// package (e.g. packet/ipv4, packet/tcp, ...).
package packet

import "fmt"
import "reflect"
import "strconv"
import "strings"

// Type represents the protocol of a packet.
type Type uint16

const (
	None Type = iota
	ARP
	Bluetooth /* TODO */
	Eth
	GRE       /* TODO */
	ICMPv4
	ICMPv6
	IGMP      /* TODO */
	IPSec     /* TODO */
	IPv4
	IPv6
	ISIS      /* TODO */
	L2TP      /* TODO */
	LLC
	LLDP      /* TODO */
	OSPF      /* TODO */
	RadioTap  /* TODO */
	Raw
	SCTP      /* TODO */
	SLL
	SNAP
	TCP
	TRILL     /* TODO */
	UDP
	UDPLite   /* TODO */
	VLAN
	WiFi      /* TODO */
	WoL       /* TODO */
)

// Packet is the interface used internally to implement packet encoding and
// decoding independently of the packet wire format.
type Packet interface {
	GetType() Type
	GetLength() uint16

	Pack(*Buffer) error
	Unpack(raw_pkt *Buffer) error

	Payload() Packet
	PayloadType() Type
	SetPayload(p Packet) error

	InitChecksum(csum uint32)

	String() string
}

var pcap_link_type_to_type_map = [][2]uint32{
	{   1, uint32(Eth)  },
	{ 113, uint32(SLL)  },
}

// Create a new type from the given PCAP link type.
func LinkType(link_type uint32) Type {
	for _, t := range pcap_link_type_to_type_map {
		if t[0] == link_type {
			return Type(t[1])
		}
	}

	return None
}

// Convert the Type to the corresponding PCAP link type.
func (pkttype Type) ToLinkType() uint32 {
	for _, t := range pcap_link_type_to_type_map {
		if t[1] == uint32(pkttype) {
			return t[0]
		}
	}

	return 0x00
}

type type_map struct {
	name    Type
	sname   string
	payload bool
}

var types_map = []type_map{
	{ None,      "None",      true  },
	{ ARP,       "ARP",       true  },
	{ Bluetooth, "Bluetooth", false },
	{ Eth,       "Eth",       false },
	{ GRE,       "GRE",       false },
	{ ICMPv4,    "ICMPv4",    true  },
	{ ICMPv6,    "ICMPv6",    true  },
	{ IGMP,      "IGMP",      true  },
	{ IPSec,     "IPSec",     false },
	{ IPv4,      "IPv4",      false },
	{ IPv6,      "IPv6",      false },
	{ ISIS,      "ISIS",      true  },
	{ L2TP,      "L2TP",      false },
	{ LLC,       "LLC",       false },
	{ LLDP,      "LLDP",      true  },
	{ OSPF,      "OSPF",      true  },
	{ RadioTap,  "RadioTap",  false },
	{ Raw,       "Data",      true  },
	{ SCTP,      "SCTP",      false },
	{ SLL,       "SLL",       false },
	{ SNAP,      "SNAP",      false },
	{ TCP,       "TCP",       false },
	{ TRILL,     "TRILL",     true  },
	{ UDP,       "UDP",       false },
	{ UDPLite,   "UDPLite",   false },
	{ VLAN,      "VLAN",      false },
	{ WiFi,      "WiFi",      false },
	{ WoL,       "WoL",       true  },
}

// Return whether the packet type is the last of the chain.
func (t Type) IsPayload() bool {
	for _, entry := range types_map {
		if entry.name == t {
			return entry.payload
		}
	}

	return true
}

func (t Type) String() string {
	for _, entry := range types_map {
		if entry.name == t {
			return entry.sname
		}
	}

	return "Data"

}

func Stringify(p Packet) string {
	value := reflect.ValueOf(p).Elem()
	name  := strings.ToLower(p.GetType().String())

	var fields []string
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		ftype := value.Type().Field(i)

		key := strings.ToLower(ftype.Name)

		if ftype.Tag.Get("name") != "" {
			key = ftype.Tag.Get("name")
		}

		if key == "skip" {
			continue
		}

		val := stringify_value(key, field)
		if val != "" {
			fields = append(fields, fmt.Sprintf("%s=%s", key, val))
		}
	}

	s := fmt.Sprintf("%s(%s)", name, strings.Join(fields, ", "))

	if p.Payload() != nil {
		s = strings.Join([]string{s, p.Payload().String()}, " | ")
	}

	return s
}

func stringify_value(key string, val reflect.Value) string {
	var s string
	var m reflect.Value

	if !val.IsValid() {
		goto end
	}

	switch val.Kind() {
	case reflect.Uint8, reflect.Uint16:
		if val.Uint() > 0 {
			if key == "sum" || key == "type" {
				s = "0x" + strconv.FormatUint(val.Uint(), 16)
			} else {
				s = strconv.FormatUint(val.Uint(), 10)
			}
		}

	case reflect.Interface, reflect.Slice, reflect.Struct:
		if val.IsNil() {
			goto end
		}

	case reflect.Bool:
		if val.Bool() {
			s = "true"
		}
	}

	m = val.MethodByName("String")
	if m.IsValid() {
		res := m.Call([]reflect.Value{})
		s = res[0].String()
	}

end:
	return s
}
