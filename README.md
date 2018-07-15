# GoARP

Manage your ARP table natively from Go.

## OSX

Inspired by the native implementation of the `arp` command, it uses sycalls to
avoid shelling out and run `arp -a`.

