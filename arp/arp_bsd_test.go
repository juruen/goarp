// +build darwin freebsd netbsd openbsd

package arp

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	arpEntryTest = "800005040800adde0504021503000000000000000000000000000000340900000000000000000000dc05000000000000042e4b5b000000000000000000000000000000000000000034090000000000000000000000000000b405000010020000c0a8010100000000000000001412080006000600008ef23f50fb000000000000"
)

func TestParseArpTable(t *testing.T) {
	buf, err := hex.DecodeString(arpEntryTest)

	assert.Nil(t, err)

	table, err := parseArpTable(buf)

	assert.Nil(t, err)
	assert.NotNil(t, table)
	assert.Equal(t, 1, len(table))
	assert.Equal(t, "192.168.1.1", table[0].IPAddr.String())
	assert.Equal(t, "00:8e:f2:3f:50:fb", table[0].HwAddr.String())
}
