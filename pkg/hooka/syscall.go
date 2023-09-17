package hooka

import "github.com/D3Ext/Hooka/core"

func Syscall(callid uint16, argh ...uintptr) (uint32, error) {
	return core.Syscall(callid, argh...)
}

func Execute(shellcode []byte) error {
	return core.Execute(shellcode)
}

func WriteMemory(inbuf []byte, destination uintptr) {
	core.WriteMemory(inbuf, destination)
}
