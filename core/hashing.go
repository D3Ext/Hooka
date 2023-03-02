package core

/*

References:
https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware

*/

import (
  "errors"
  "bytes"
  "encoding/binary"

  // Third-party
  "github.com/Binject/debug/pe"
)

// Check if hash is a valid function and return its proc
func FuncFromHash(hash string, dll string) (uint16, string, error) {
  dll_pe, err := pe.Open(dll) // Open and parse dll as a PE
  if err != nil {
    return 0, "", err
  }
  defer dll_pe.Close()

  exports, err := dll_pe.Exports() // Get exported functions
  if err != nil {
    return 0, "", err
  }

  for _, ex := range exports {
    if (StrToSha1(ex.Name) == hash) {

      offset := rvaToOffset(dll_pe, ex.VirtualAddress)
      bBytes, err := dll_pe.Bytes()
      if err != nil {
        return 0, "", err
      }

      buff := bBytes[offset : offset+10]
      if !bytes.HasPrefix(buff, HookCheck) {
        return 0, "", MayBeHookedError{Foundbytes: buff}
      }
      
      sysId := binary.LittleEndian.Uint16(buff[4:8])
      return sysId, ex.Name, nil
    }
  }

  return 0, "", errors.New("function not found!")
}

// Convert string to sha1
func HashFromFunc(funcname string) (string) {
  return StrToSha1(funcname)
}


