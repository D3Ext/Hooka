package core

/*

References:
https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware

*/

import (
	"bytes"
	"encoding/binary"
	"errors"

	// Third-party
	"github.com/Binject/debug/pe"
	"github.com/awgh/rawreader"
)

// Check if hash is a valid function and return its proc
func FuncFromHash(hash string, dll string, hashing_func func(str string) string) (uint16, string, error) {
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

	return 0, "", errors.New("function not found!")
}

func HalosFuncFromHash(hash string, hashing_func func(str string) string) (uint16, string, error) {
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
