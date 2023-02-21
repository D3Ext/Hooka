package core

/*

This package exports all windows struct which are used

*/

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
  VirtualAddress  uint32
  Size            uint32
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

type IMAGE_DOS_HEADER struct { // DOS .EXE header
  E_magic    uint16     // Magic number
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
  E_res2     [10]uint16 // Reserved words
  E_lfanew   uint16     // File address of new exe header
}



