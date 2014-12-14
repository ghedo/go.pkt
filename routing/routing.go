// Provides network routing information about the system.
package routing

import "fmt"
import "net"
import "strings"

type Route struct {
	Default bool
	SrcNet  *net.IPNet
	DstNet  *net.IPNet
	Gateway net.IP
	Iface   *net.Interface
	PrefSrc net.IP
}

// Return the route that matches the given destination address.
func RouteTo(dst net.IP) (*Route, error) {
	var def *Route

	routes, err := Routes()
	if err != nil {
		return nil, fmt.Errorf("Could not get routes: %s", err)
	}

	for _, r := range routes {
		if r.Default &&
		   r.Iface != nil &&
		   r.Iface.Flags & net.FlagLoopback == 0 {
			def = r
			continue
		}

		if r.DstNet != nil &&
		   r.DstNet.Contains(dst) {
			return r, nil
		}
	}

	return def, nil
}

func (r *Route) String() string {
	var parts []string

	if r.Default {
		parts = append(parts, "default")
	} else if r.DstNet != nil {
		parts = append(parts, r.DstNet.String())
	}

	if r.SrcNet != nil {
		src := fmt.Sprintf("from %s", r.DstNet.String())
		parts = append(parts, src)
	}

	if r.Gateway != nil {
		gateway := fmt.Sprintf("via %s", r.Gateway.String())
		parts = append(parts, gateway)
	}

	if r.Iface != nil {
		iface := fmt.Sprintf("dev %s", r.Iface.Name)
		parts = append(parts, iface)
	}


	if r.PrefSrc != nil {
		prefsrc := fmt.Sprintf("src %s", r.PrefSrc.String())
		parts = append(parts, prefsrc)
	}

	return strings.Join(parts, " ")
}
