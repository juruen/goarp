package arp

import "net"

// Entry contaiins an IP address and its corresponding
// hardware address
type Entry struct {
	IPAddr net.IP
	HwAddr net.HardwareAddr
}
