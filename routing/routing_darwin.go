package routing

import "net"

func Routes() ([]*Route, error) {
	return []*Route{}, nil
}

func RouteTo(dst net.IP) (*Route, error) {
	return &Route{}, nil
}
