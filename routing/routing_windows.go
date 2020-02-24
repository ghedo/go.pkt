package routing

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

type socketAddrInet struct {
	Family uint16
	Addr   [26]byte
}

type ipAddressPrefix struct {
	Prefix       socketAddrInet
	PrefixLength uint8
	padding      uint16
}

type mibIPForwardRow2 struct {
	InterfaceLuid        uint64
	InterfaceIndex       uint32
	DestinationPrefix    ipAddressPrefix
	NextHop              socketAddrInet
	SitePrefixLength     uint8
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             uint32
	Loopback             uint8
	AutoconfigureAddress uint8
	Publish              uint8
	Immortal             uint8
	Age                  uint32
	Origin               uint32
}

type socketAddress struct {
	Sockaddr       *syscall.RawSockaddrAny
	SockaddrLength int32
}

type ipAdapterUnicastAddress struct {
	Length             uint32
	Flags              uint32
	Next               *ipAdapterUnicastAddress
	Address            socketAddress
	PrefixOrigin       int32
	SuffixOrigin       int32
	DadState           int32
	ValidLifetime      uint32
	PreferredLifetime  uint32
	LeaseLifetime      uint32
	OnLinkPrefixLength uint8
}

type ipAdapterAnycastAddress struct {
	Length  uint32
	Flags   uint32
	Next    *ipAdapterAnycastAddress
	Address socketAddress
}

type ipAdapterMulticastAddress struct {
	Length  uint32
	Flags   uint32
	Next    *ipAdapterMulticastAddress
	Address socketAddress
}

type ipAdapterDNSServerAddress struct {
	Length   uint32
	Reserved uint32
	Next     *ipAdapterDNSServerAddress
	Address  socketAddress
}

type ipAdapterPrefix struct {
	Length       uint32
	Flags        uint32
	Next         *ipAdapterPrefix
	Address      socketAddress
	PrefixLength uint32
}

type ipAdapterWinsServerAddress struct {
	Length   uint32
	Reserved uint32
	Next     *ipAdapterWinsServerAddress
	Address  socketAddress
}

type ipAdapterGatewayAddress struct {
	Length   uint32
	Reserved uint32
	Next     *ipAdapterGatewayAddress
	Address  socketAddress
}

type ipAdapterAddresses struct {
	Length                 uint32
	IfIndex                uint32
	Next                   *ipAdapterAddresses
	AdapterName            *byte
	FirstUnicastAddress    *ipAdapterUnicastAddress
	FirstAnycastAddress    *ipAdapterAnycastAddress
	FirstMulticastAddress  *ipAdapterMulticastAddress
	FirstDNSServerAddress  *ipAdapterDNSServerAddress
	DNSSuffix              *uint16
	Description            *uint16
	FriendlyName           *uint16
	PhysicalAddress        [syscall.MAX_ADAPTER_ADDRESS_LENGTH]byte
	PhysicalAddressLength  uint32
	Flags                  uint32
	Mtu                    uint32
	IfType                 uint32
	OperStatus             uint32
	Ipv6IfIndex            uint32
	ZoneIndices            [16]uint32
	FirstPrefix            *ipAdapterPrefix
	TransmitLinkSpeed      uint64
	ReceiveLinkSpeed       uint64
	FirstWinsServerAddress *ipAdapterWinsServerAddress
	FirstGatewayAddress    *ipAdapterGatewayAddress
	/* more fields might be present here. */
}

var (
	iphlpapi                 = syscall.NewLazyDLL("Iphlpapi.dll")
	getBestRoute2Proc        = iphlpapi.NewProc("GetBestRoute2")
	getAdaptersAddressesProc = iphlpapi.NewProc("GetAdaptersAddresses")
)

func getAdaptersAddresses(family uint32, flags uint32, reserved uintptr, adapterAddresses *ipAdapterAddresses, sizePointer *uint32) error {

	ret, _, _ := getAdaptersAddressesProc.Call(
		uintptr(family),
		uintptr(flags),
		uintptr(reserved),
		uintptr(unsafe.Pointer(adapterAddresses)),
		uintptr(unsafe.Pointer(sizePointer)))

	if ret != 0 {
		return syscall.Errno(ret)
	}
	return nil
}

func getBestRoute(dst net.IP, bestRoute *mibIPForwardRow2, bestSourceAddress *socketAddrInet) error {

	var addrPtr uintptr
	switch len(dst) {
	case net.IPv4len:
		var rawIpv4 syscall.RawSockaddrInet4
		rawIpv4.Family = syscall.AF_INET
		copy(rawIpv4.Addr[:], dst[:])
		addrPtr = uintptr(unsafe.Pointer(&rawIpv4))

	case net.IPv6len:
		var rawIpv6 syscall.RawSockaddrInet6
		rawIpv6.Family = syscall.AF_INET6
		copy(rawIpv6.Addr[:], dst[:])
		addrPtr = uintptr(unsafe.Pointer(&rawIpv6))

	default:
		return fmt.Errorf("invalid destination IP address")
	}

	ret, _, _ := getBestRoute2Proc.Call(
		0,
		0,
		0,
		addrPtr,
		0,
		uintptr(unsafe.Pointer(bestRoute)),
		uintptr(unsafe.Pointer(bestSourceAddress)))

	if ret != 0 {
		return syscall.Errno(ret)
	}
	return nil
}

func adapterAddresses() ([]*ipAdapterAddresses, error) {
	var buffer []byte
	length := uint32(15000) // initial size

	flags := uint32(0x00000010 /*GAA_FLAG_INCLUDE_PREFIX*/ | 0x00000080 /*GAA_FLAG_INCLUDE_GATEWAYS*/)

	var adapterAddresses []*ipAdapterAddresses

	for {
		buffer = make([]byte, length)
		err := getAdaptersAddresses(
			syscall.AF_UNSPEC,
			flags,
			0,
			(*ipAdapterAddresses)(unsafe.Pointer(&buffer[0])), &length)
		if err == nil {
			if length == 0 {
				return adapterAddresses, nil
			}
			break
		}
		if err.(syscall.Errno) != syscall.ERROR_BUFFER_OVERFLOW {
			return adapterAddresses, os.NewSyscallError("getadaptersaddresses", err)
		}
		if length <= uint32(len(buffer)) {
			return adapterAddresses, os.NewSyscallError("getadaptersaddresses", err)
		}
	}

	for adapterAddress := (*ipAdapterAddresses)(unsafe.Pointer(&buffer[0])); adapterAddress != nil; adapterAddress = adapterAddress.Next {
		adapterAddresses = append(adapterAddresses, adapterAddress)
	}
	return adapterAddresses, nil
}

func getGatewayAddresses(iface *net.Interface) ([]net.IP, error) {
	adapterAddresses, err := adapterAddresses()
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, adapterAddress := range adapterAddresses {
		index := adapterAddress.IfIndex
		if index == 0 { // ipv6IfIndex is a substitute for ifIndex
			index = adapterAddress.Ipv6IfIndex
		}
		if iface.Index == int(index) {
			for gatewayAddress := adapterAddress.FirstGatewayAddress; gatewayAddress != nil; gatewayAddress = gatewayAddress.Next {
				addr, err := gatewayAddress.Address.Sockaddr.Sockaddr()
				if err != nil {
					return nil, os.NewSyscallError("sockaddr", err)
				}
				switch addr := addr.(type) {
				case *syscall.SockaddrInet4:
					ips = append(ips, net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3]))
				case *syscall.SockaddrInet6:
					ip := make(net.IP, net.IPv6len)
					copy(ip, addr.Addr[:])
					ips = append(ips, ip)
				}
			}
		}
	}
	return ips, nil
}

func socketAddrInetToIP(sockAddr *socketAddrInet) (net.IP, error) {
	var ip net.IP
	switch sockAddr.Family {
	case syscall.AF_INET:
		ipv4 := (*syscall.RawSockaddrInet4)(unsafe.Pointer(sockAddr))
		ip = net.IPv4(ipv4.Addr[0], ipv4.Addr[1], ipv4.Addr[2], ipv4.Addr[3])

	case syscall.AF_INET6:
		ipv6 := (*syscall.RawSockaddrInet6)(unsafe.Pointer(sockAddr))
		ip = make(net.IP, net.IPv6len)
		copy(ip, ipv6.Addr[:])

	default:
		return nil, fmt.Errorf("invalid socketAddrInet address")
	}
	return ip, nil

}

func Routes() ([]*Route, error) {
	return []*Route{}, nil
}

func RouteTo(dst net.IP) (*Route, error) {

	var bestRoute mibIPForwardRow2
	var bestSourceAddress socketAddrInet

	err := getBestRoute(dst, &bestRoute, &bestSourceAddress)
	if err != nil {
		return nil, err
	}

	srcIP, err := socketAddrInetToIP(&bestSourceAddress)
	if err != nil {
		return nil, err
	}

	ipNet := &net.IPNet{
		IP:   srcIP,
		Mask: net.CIDRMask(int(bestRoute.DestinationPrefix.PrefixLength), 8*len(srcIP)),
	}

	iface, err := net.InterfaceByIndex(int(bestRoute.InterfaceIndex))
	if err != nil {
		return nil, err
	}

	ips, err := getGatewayAddresses(iface)
	if err != nil {
		return nil, err
	}

	var gateway net.IP
	gateway = nil

	if len(ips) >= 1 {
		gateway = ips[0]
	}

	route := &Route{
		Default: false,
		Gateway: gateway,
		SrcNet:  nil,
		DstNet:  ipNet,
		Iface:   iface,
	}

	return route, nil
}
