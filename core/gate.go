package core

/*

References:


*/

import (
  "errors"
  "unsafe"
  "strings"
  "encoding/binary"
  
  "github.com/Binject/debug/pe"
)

func GetSysId(funcname string) (uint16, error) {

  ntdll_handle, _ := inMemLoads(string([]byte{'n', 't', 'd', 'l', 'l'}))

  if (ntdll_handle == 0) {
    return 0, errors.New("an error has ocurred while getting ntdll.dll handle!")
  }

  exports := getExport(ntdll_handle)

  for _, exp := range exports {
    if (strings.ToLower(funcname) == strings.ToLower(exp.Name)) {

      buff := make([]byte, 10)

      if exp.VirtualAddress <= ntdll_handle {
        return 0, errors.New("an error has ocurred getting syscall id")
      }

      memcpy(uintptr(unsafe.Pointer(&buff[0])), uintptr(exp.VirtualAddress), 10)

      // Check if function isn't hooked
      if buff[0] == 0x4c && buff[1] == 0x8b && buff[2] == 0xd1 && buff[3] == 0xb8 && buff[6] == 0x00 && buff[7] == 0x00 {
        // Return syscall id
        return binary.LittleEndian.Uint16(buff[4:8]), nil

      } else { // Enter here if function seems to be hooked
        
        for i := uintptr(1); i <= 500; i++ { // Loop 500 times to get a valid syscall

          memcpy(uintptr(unsafe.Pointer(&buff[0])), uintptr(exp.VirtualAddress + i*IDX), 10)
          if buff[0] == 0x4c && buff[1] == 0x8b && buff[2] == 0xd1 && buff[3] == 0xb8 && buff[6] == 0x00 && buff[7] == 0x00 {
            return uint16Down(buff[4:8], uint16(i)), nil // Return syscall
          }

          memcpy(uintptr(unsafe.Pointer(&buff[0])), uintptr(exp.VirtualAddress - i*IDX), 10)
          if buff[0] == 0x4c && buff[1] == 0x8b && buff[2] == 0xd1 && buff[3] == 0xb8 && buff[6] == 0x00 && buff[7] == 0x00 {
            return uint16Up(buff[4:8], uint16(i)), nil
          }
        }
      }

      return getDiskSysId(funcname)
    }
  }

  return getDiskSysId(funcname)
}

func getDiskSysId(funcname string) (uint16, error) {

  ntdll_path := string(
    []byte{
      'c', ':', '\\', 'w', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l',
    },
  )

  ntdll_pe, err := pe.Open(ntdll_path)
  if err != nil {
    return 0, err
  }

  exports, err := ntdll_pe.Exports()
  if err != nil {
    return 0, err
  }

  for _, exp := range exports {
    if (strings.ToLower(funcname) == strings.ToLower(exp.Name)) {

      offset := rvaToOffset(ntdll_pe, exp.VirtualAddress)
      b, err := ntdll_pe.Bytes()
      if err != nil {
        return 0, err
      }

      buff := b[offset : offset+10]

      // Check if function isn't hooked
      if buff[0] == 0x4c && buff[1] == 0x8b && buff[2] == 0xd1 && buff[3] == 0xb8 && buff[6] == 0x00 && buff[7] == 0x00 {
        // Return syscall id
        return binary.LittleEndian.Uint16(buff[4:8]), nil

      } else { // Enter here if function seems to be hooked
        
        for i := uintptr(1); i <= 500; i++ { // Loop 500 times to get a valid syscall

          if *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[0])) + i*IDX)) == 0x4c &&
            *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[1])) + i*IDX)) == 0x8b &&
            *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[2])) + i*IDX)) == 0xd1 &&
            *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[3])) + i*IDX)) == 0xb8 &&
            *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[6])) + i*IDX)) == 0x00 &&
            *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[7])) + i*IDX)) == 0x00 {

            buff[4] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[4])) + i*IDX))
            buff[5] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[5])) + i*IDX))

            return uint16Down(buff[4:8], uint16(i)), nil // Return syscall
          }

          if *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[0])) - i*IDX)) == 0x4c &&
            *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[1])) - i*IDX)) == 0x8b &&
            *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[2])) - i*IDX)) == 0xd1 &&
            *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[3])) - i*IDX)) == 0xb8 &&
            *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[6])) - i*IDX)) == 0x00 &&
            *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[7])) - i*IDX)) == 0x00 {

            buff[4] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[4])) - i*IDX))
            buff[5] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[5])) - i*IDX))

            return uint16Up(buff[4:8], uint16(i)), nil
          }
        }
      }

      return 0, errors.New("syscall ID not found")
    }
  }

  return 0, errors.New("syscall ID not found")
}


