// +build darwin freebsd netbsd openbsd

package arp

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

// DumpArpTable returns the BSD ARP table
func DumpArpTable() ([]Entry, error) {
	buf, err := dumpArpTableSyscall()

	if err != nil {
		return nil, err
	}

	return parseArpTable(buf)
}

type sockaddrInArp struct {
	len    uint8
	family uint8
	port   uint16
	addr   [4]byte
}

func dumpArpTableSyscall() ([]byte, error) {
	mib := [6]int32{
		syscall.CTL_NET,
		syscall.AF_ROUTE,
		0,
		syscall.AF_INET,
		syscall.NET_RT_FLAGS,
		syscall.RTF_LLINFO,
	}

	size := uintptr(0)

	_, _, errno := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		6,
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		0)

	if errno != 0 {
		return nil, errno
	}

	if size == 0 {
		return nil, nil // empty table
	}

	var bs []byte
	for {
		bs = make([]byte, size)
		_, _, errno := syscall.Syscall6(
			syscall.SYS___SYSCTL,
			uintptr(unsafe.Pointer(&mib[0])),
			6,
			uintptr(unsafe.Pointer(&bs[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			0)

		if errno == syscall.ENOMEM {
			continue
		}

		if errno == 0 {
			break
		}

		return nil, errno
	}

	return bs, nil
}

// parseArpTable parses an arp table that is given by a native
// BSD sycall to fetch routing and link layer information
func parseArpTable(buf []byte) ([]Entry, error) {
	table := make([]Entry, 0)

	offset := 0
	hexstr := ""
	for offset < len(buf) {
		header := (*syscall.RtMsghdr)(unsafe.Pointer(&buf[offset]))
		ipAddrPtr := offset + syscall.SizeofRtMsghdr
		ipAddr := (*sockaddrInArp)(unsafe.Pointer(&buf[ipAddrPtr]))

		if ipAddr.family != syscall.AF_INET {
			continue
		}

		datalinkPtr := ipAddrPtr + int(ipAddr.len)
		datalink := (*syscall.SockaddrDatalink)(unsafe.Pointer(&buf[datalinkPtr]))

		hwAddrs := make([]string, 0)
		for i := 0; i < int(datalink.Alen); i++ {
			hwAddrs = append(hwAddrs, fmt.Sprintf("%02x", uint8(datalink.Data[i])))
		}

		ip := net.IPv4(ipAddr.addr[0], ipAddr.addr[1], ipAddr.addr[2], ipAddr.addr[3])
		hwAddr, err := net.ParseMAC(strings.Join(hwAddrs, ":"))

		if err != nil {
			return nil, err
		}

		table = append(table, Entry{IPAddr: ip, HwAddr: hwAddr})

		if offset == 0 {
			for i := 0; i < int(header.Msglen); i++ {
				hexstr = hexstr + fmt.Sprintf("%02x", uint8(*(*uint8)(unsafe.Pointer(&buf[i]))))
			}
		}

		offset = offset + int(header.Msglen)
	}

	fmt.Println(hexstr)
	return table, nil
}
