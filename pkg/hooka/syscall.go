package hooka

import "github.com/D3Ext/Hooka/evasion"

func Syscall(callid uint16, argh ...uintptr) (uint32, error) {
	return evasion.Syscall(callid, argh...)
}


