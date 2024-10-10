package shellcode

/*

This package exports all windows struct which are used

*/

import (
	"unsafe"
)

const (
	IDX = 32
)

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

type IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER

type IMAGE_OPTIONAL_HEADER32 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32 // Different from 64 bit header
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
	DataDirectory               uintptr
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
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

type IMAGE_NT_HEADER struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

type PEB struct {
	InheritedAddressSpace    byte        // BYTE	0
	ReadImageFileExecOptions byte        // BYTE	1
	BeingDebugged            byte        // BYTE	2
	reserved2                [1]byte     // BYTE 3
	Mutant                   uintptr     // BYTE 4
	ImageBaseAddress         uintptr     // BYTE 8
	Ldr                      uintptr     // PPEB_LDR_DATA
	ProcessParameters        uintptr     // PRTL_USER_PROCESS_PARAMETERS
	reserved4                [3]uintptr  // PVOID
	AtlThunkSListPtr         uintptr     // PVOID
	reserved5                uintptr     // PVOID
	reserved6                uint32      // ULONG
	reserved7                uintptr     // PVOID
	reserved8                uint32      // ULONG
	AtlThunkSListPtr32       uint32      // ULONG
	reserved9                [45]uintptr // PVOID
	reserved10               [96]byte    // BYTE
	PostProcessInitRoutine   uintptr     // PPS_POST_PROCESS_INIT_ROUTINE
	reserved11               [128]byte   // BYTE
	reserved12               [1]uintptr  // PVOID
	SessionId                uint32      // ULONG
}

// https://github.com/elastic/go-windows/blob/master/ntdll.go#L77
type PROCESS_BASIC_INFORMATION struct {
	reserved1                    uintptr    // PVOID
	PebBaseAddress               uintptr    // PPEB
	reserved2                    [2]uintptr // PVOID
	UniqueProcessId              uintptr    // ULONG_PTR
	InheritedFromUniqueProcessID uintptr    // PVOID
}

type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

type PTHREAD_BASIC_INFORMATION struct {
	exitStatus      int32
	pTebBaseAddress uintptr
	clientId        CLIENT_ID
	AffinityMask    uintptr
	Priority        int
	BasePriority    int
	v               int
}

type SC_SERVICE_TAG_QUERY struct {
	processId  uint32
	serviceTag uint32
	reserved   uint32
	pBuffer    unsafe.Pointer
}
