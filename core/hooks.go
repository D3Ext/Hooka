package core

/*

This package provides a function to detect Windows API hooked functions (e.g. CreateRemoteThread)

References:
https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions
https://github.com/C-Sto/BananaPhone

*/

import (
  "fmt"
  "errors"
  "strings"

  // Third-party packages
  "github.com/Binject/debug/pe"
)

func DetectHooks() ([]string, error) {
  var hooked_functions []string

  ntdll_pe, err := pe.Open(ntdllpath) // Open and parse ntdll.dll as a PE
  if err != nil {
    return hooked_functions, err
  }
  defer ntdll_pe.Close()

  exports, err := ntdll_pe.Exports() // Get exported functions
  if err != nil {
    return hooked_functions, err
  }

  for _, exp := range exports { // Iterate over them
    offset := RvaToOffset(ntdll_pe, exp.VirtualAddress) // Get RVA offset
    bBytes, err := ntdll_pe.Bytes() // Get bytes from ntdll.dll
    if err != nil {
      return hooked_functions, err
    }

    buff := bBytes[offset : offset+10]
    _, err = CheckBytes(buff) // Get syscall ID (if function is hooked it returns a custom error)
    var hook_err MayBeHookedError

    if (len(exp.Name) > 3) { // Avoid errors by checking function name length
      if exp.Name[0:2] == "Nt" || exp.Name[0:2] == "Zw" { // Just use functions which start by "Nt" or "Zw"
        if errors.As(err, &hook_err) == false { // Check error
          /*if bytes.HasPrefix(buff, []byte{0xE9}) == false {
            fmt.Println(exp.Name)
          }*/
          hooked_functions = append(hooked_functions, exp.Name)
        }
      }
    }
  }

  return hooked_functions, nil
}

func IsHooked(funcname string) (bool, error) {
  all_hooks, err := DetectHooks()
  if err != nil {
    return false, err
  }

  for _, h := range all_hooks {
    if (strings.ToLower(funcname) == strings.ToLower(h)) {
      return true, nil
    }
  }

  return false, nil
}


