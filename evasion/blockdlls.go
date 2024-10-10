package evasion

import (
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
	"errors"
)

/*

typedef struct _PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY {
  union {
    DWORD Flags;
    struct {
      DWORD MicrosoftSignedOnly : 1;
      DWORD StoreSignedOnly : 1;
      DWORD MitigationOptIn : 1;
      DWORD AuditMicrosoftSignedOnly : 1;
      DWORD AuditStoreSignedOnly : 1;
      DWORD ReservedFlags : 27;
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME;
} PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, *PPROCESS_MITIGATION_BINARY_SIGNATURE_POLICY;

*/

type PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY struct {
	Flags uint32
}

// block non Microsoft-signed DLLs to inject in current process
func BlockDLLs() error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	SetProcessMitigationPolicy := kernel32.NewProc("SetProcessMitigationPolicy")

	var ProcessSignaturePolicy uint32 = 8
	var sp PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY

	// set MicrosoftSignedOnly
	sp.Flags = 0x1

	ret, _, err := SetProcessMitigationPolicy.Call(
		uintptr(ProcessSignaturePolicy),
		uintptr(unsafe.Pointer(&sp)),
		unsafe.Sizeof(sp),
	)

	if ret == 0 {
		return errors.New(fmt.Sprintf("error: %s\nSetProcessMitigationPolicy returned %x", err, ret))
	}

	return nil
}

// launch a program (C:\Windows\System32\notepad.exe) with BlockDLLs enabled
func CreateProcessBlockDLLs(cmd string) error {
  kernel32 := windows.NewLazyDLL("kernel32.dll")
  InitializeProcThreadAttributeList := kernel32.NewProc("InitializeProcThreadAttributeList")
  UpdateProcThreadAttribute := kernel32.NewProc("UpdateProcThreadAttribute")
  GetProcessHeap := kernel32.NewProc("GetProcessHeap")
  HeapAlloc := kernel32.NewProc("HeapAlloc")
  HeapFree := kernel32.NewProc("HeapFree")
  CreateProcess := kernel32.NewProc("CreateProcessW")

  procThreadAttributeSize := uintptr(0)
  InitializeProcThreadAttributeList.Call(0, 2, 0, uintptr(unsafe.Pointer(&procThreadAttributeSize)))

  procHeap, _, err := GetProcessHeap.Call()
  if procHeap == 0 {
    return err
  }

  attributeList, _, err := HeapAlloc.Call(procHeap, 0, procThreadAttributeSize)
  if attributeList == 0 {
    return err
  }
  defer HeapFree.Call(procHeap, 0, attributeList)

  var si StartupInfoEx
  si.AttributeList = (*PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(attributeList))

  InitializeProcThreadAttributeList.Call(uintptr(unsafe.Pointer(si.AttributeList)), 2, 0, uintptr(unsafe.Pointer(&procThreadAttributeSize)))

  mitigate := 0x20007
  nonms := uintptr(0x100000000000|0x1000000000)

  r, _, err := UpdateProcThreadAttribute.Call(uintptr(unsafe.Pointer(si.AttributeList)), 0, uintptr(mitigate), uintptr(unsafe.Pointer(&nonms)), uintptr(unsafe.Sizeof(nonms)), 0, 0)
  if r == 0 {
    return err
  }

  commandline, err := windows.UTF16PtrFromString(cmd)
  if err != nil {
    return err
  }

  var pi ProcessInformation
  si.Cb = uint32(unsafe.Sizeof(si))
  flags := windows.EXTENDED_STARTUPINFO_PRESENT

  r, _, err = CreateProcess.Call(
    0,
		uintptr(unsafe.Pointer(commandline)),
		0,
		0,
		1,
		uintptr(uint32(flags)),
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
  )

  if r == 0 {
    return err
  }

  return nil
}
