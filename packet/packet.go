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
    /* Return the type of the packet */
    GetType() Type

    /* Return the length of the packet including the payload if present */
    GetLength() uint16

    /* Check if the packet matches another packet */
    Equals(other Packet) bool

    /* Check if the packet is an answer to another packet */
    Answers(other Packet) bool

    /* Encode the packet and write it to the given buffer */
    Pack(out *Buffer) error

    /* Decode the packet from the given buffer */
    Unpack(in *Buffer) error

    /* Return the payload of the packet or nil */
    Payload() Packet

    /* Initialize the payload of the packet */
    SetPayload(payload Packet) error

    /* Try to guess the type of the payload */
    GuessPayloadType() Type

    /* Initialize the checksum of the packet with the given seed */
    InitChecksum(seed uint32)

    String() string
}

var pcap_link_type_to_type_map = [][2]uint32{
    {   1, uint32(Eth)      },
    { 113, uint32(SLL)      },
    { 127, uint32(RadioTap) },
    { 228, uint32(IPv4)     },
    { 229, uint32(IPv6)     },
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
    case SNAP:      return "SNAP"
    case SLL:       return "SLL"
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

func Compare(a, b Packet) bool {
    if a == nil || b == nil {
        return a == b
    }

    if a.GetType() != b.GetType() {
        return false
    }

    aval := reflect.ValueOf(a).Elem()
    bval := reflect.ValueOf(b).Elem()

    for i := 0; i < aval.NumField(); i++ {
        ftype := aval.Type().Field(i)

        if ftype.Tag.Get("cmp") == "skip" {
            continue
        }

        if !compare_value(aval.Field(i), bval.Field(i)) {
            fmt.Println(aval.Type().Field(i).Name)
            return false
        }
    }

    return true
}

func compare_value(a, b reflect.Value) bool {
    if a.Type() != b.Type() {
        return false
    }

    m := a.MethodByName("Equal")
    if m.IsValid() {
        res := m.Call([]reflect.Value{b})
        return res[0].Bool()
    }

    switch a.Kind() {
    case reflect.Bool:
        return a.Bool() == b.Bool()

    case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
        return a.Uint() == b.Uint()

    case reflect.Array:
        for i := 0; i < a.Len(); i++ {
            if !compare_value(a.Index(i), b.Index(i)) {
                return false
            }
        }

        return true

    case reflect.Slice:
        if a.IsNil() != b.IsNil() {
            return false
        }

        if a.Len() != b.Len() {
            return false
        }

        if a.Pointer() == b.Pointer() {
            return true
        }

        for i := 0; i < a.Len(); i++ {
            if !compare_value(a.Index(i), b.Index(i)) {
                return false
            }
        }

        return true

    case reflect.Interface:
        return true

    default:
        return false
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

        if ftype.Tag.Get("string") != "" {
            key = ftype.Tag.Get("string")
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
    case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
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
