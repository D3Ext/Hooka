package core

/*

References:
https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware

*/

import (
  "errors"

  "golang.org/x/sys/windows"

  // Third-party
  "github.com/Binject/debug/pe"
)

// Check if hash is a valid function and return its proc
func FuncFromHash(hash string, dll string) (*windows.LazyProc, string, error) {
  dll_pe, err := pe.Open(dll) // Open and parse dll as a PE
  if err != nil {
    return new(windows.LazyProc), "", err
  }
  defer dll_pe.Close()

  exports, err := dll_pe.Exports() // Get exported functions
  if err != nil {
    return new(windows.LazyProc), "", err
  }

  for _, ex := range exports {
    if (StrToSha1(ex.Name) == hash) {
      return windows.NewLazyDLL(dll).NewProc(ex.Name), ex.Name, nil
    }
  }

  return new(windows.LazyProc), "", errors.New("function not found!")
}

// Convert string to sha1
func HashFromFunc(funcname string) (string) {
  return StrToSha1(funcname)
}


