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

// Provides the basic interfaces for implementing packet encoders and decoders.
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
	LLC       /* TODO */
	LLDP      /* TODO */
	OSPF      /* TODO */
	RadioTap  /* TODO */
	Raw
	SCTP      /* TODO */
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

var ethertype_to_type_map = [][2]uint16{
	{ 0x0000, uint16(None)  },
	{ 0x0001, uint16(LLC)   },
	{ 0x0800, uint16(IPv4)  },
	{ 0x0806, uint16(ARP)   },
	{ 0x0842, uint16(WoL)   },
	{ 0x22F3, uint16(TRILL) },
	{ 0x8100, uint16(VLAN)  },
	{ 0x86DD, uint16(IPv6)  },
	{ 0x88A8, uint16(VLAN)  }, /* QinQ */
	{ 0x88CC, uint16(LLDP)  },
}

// Create a new Type from the given EtherType.
func EtherType(ethertype uint16) Type {
	for _, t := range ethertype_to_type_map {
		if t[0] == ethertype {
			return Type(t[1])
		}
	}

	return Type(ethertype)
}

// Convert the Type to the corresponding EtherType.
func (pkttype Type) ToEtherType() uint16 {
	for _, t := range ethertype_to_type_map {
		if t[1] == uint16(pkttype) {
			return t[0]
		}
	}

	return uint16(pkttype)
}

var ipv4proto_to_type_map = [][2]uint16{
	{ 0x01, uint16(ICMPv4)  },
	{ 0x02, uint16(IGMP)    },
	{ 0x06, uint16(TCP)     },
	{ 0x11, uint16(UDP)     },
	{ 0x29, uint16(IPv6)    },
	{ 0x2B, uint16(IPv6)    }, /* IPv6-Route */
	{ 0x2C, uint16(IPv6)    }, /* IPv6-Frag */
	{ 0x2F, uint16(GRE)     },
	{ 0x32, uint16(IPSec)   }, /* IPSec ESP */
	{ 0x33, uint16(IPSec)   }, /* IPSec AH */
	{ 0x3A, uint16(ICMPv6)  },
	{ 0x3B, uint16(IPv6)    }, /* IPv6-NoNxt */
	{ 0x3C, uint16(IPv6)    }, /* IPv6-Opts */
	{ 0x59, uint16(OSPF)    },
	{ 0x73, uint16(L2TP)    },
	{ 0x7C, uint16(ISIS)    },
	{ 0x84, uint16(SCTP)    },
	{ 0x88, uint16(UDPLite) },
}

// Create a new Type from the given IP protocol ID.
func IPProtocol(protocol uint8) Type {
	for _, t := range ipv4proto_to_type_map {
		if t[0] == uint16(protocol) {
			return Type(t[1])
		}
	}

	return Type(protocol)
}

// Convert the Type to the corresponding IP protocol ID.
func (pkttype Type) ToIPProtocol() uint8 {
	for _, t := range ipv4proto_to_type_map {
		if t[1] == uint16(pkttype) {
			return uint8(t[0])
		}
	}

	return uint8(pkttype)
}

var pcap_link_type_to_type_map = [][2]uint32{
	{ 0x01, uint32(Eth)  },
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

// Return whether the packet type is the last of the chain.
func (t Type) IsPayload() bool {
	switch t {
	case Bluetooth: return false
	case WiFi:     return false
	case Eth:       return false
	case GRE:       return false
	case IPSec:     return false
	case IPv4:      return false
	case IPv6:      return false
	case L2TP:      return false
	case LLC:       return false
	case RadioTap:  return false
	case SCTP:      return false
	case TCP:       return false
	case UDP:       return false
	case UDPLite:   return false
	case VLAN:      return false
	default:        return true
	}
}

func (t Type) String() string {
	switch t {
	case ARP:       return "ARP"
	case Bluetooth: return "Bluetooth"
	case Eth:       return "Ethernet"
	case GRE:       return "GRE"
	case ICMPv4:    return "ICMPv4"
	case ICMPv6:    return "ICMPv6"
	case IGMP:      return "IGMP"
	case IPSec:     return "IPSec"
	case IPv4:      return "IPv4"
	case IPv6:      return "IPv6"
	case ISIS:      return "IS-IS"
	case L2TP:      return "L2TP"
	case LLC:       return "LLC"
	case LLDP:      return "LLDP"
	case None:      return "None"
	case OSPF:      return "OSPF"
	case RadioTap:  return "RadioTap"
	case SCTP:      return "SCTP"
	case TCP:       return "TCP"
	case TRILL:     return "TRILL"
	case UDPLite:   return "UDP Lite"
	case UDP:       return "UDP"
	case VLAN:      return "VLAN"
	case WiFi:      return "WiFi"
	case WoL:       return "WoL"
	/* case Raw: */
	default:        return "Data"
	}
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
