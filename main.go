package main

import (
	"fmt"

	"github.com/juruen/goarp/arp"
)

func main() {
	table, err := arp.DumpArpTable()

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(table)
	}
}
