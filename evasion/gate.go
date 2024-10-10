package evasion

import (
	"errors"
	//"fmt"
	"strings"

	"github.com/Binject/debug/pe"
	"github.com/awgh/rawreader"
)

// Return syscall from memory, if it fails it tries to get syscall from disk (using halo's gate technique)
func GetSysId(funcname string) (uint16, error) {

	var ntdll_pe *pe.File
	var err error

	s, si := inMemLoads(string([]byte{'n', 't', 'd', 'l', 'l'})) // Load ntdll in memory

	rr := rawreader.New(uintptr(s), int(si))
	ntdll_pe, err = pe.NewFileFromMemory(rr) // Parse PE file
	if err != nil {
		return 0, err
	}

	exports, err := ntdll_pe.Exports()
	if err != nil {
		return 0, err
	}

	for _, exp := range exports {
		if strings.ToLower(funcname) == strings.ToLower(exp.Name) {

			offset := rvaToOffset(ntdll_pe, exp.VirtualAddress)
			bBytes, err := ntdll_pe.Bytes()
			if err != nil {
				return 0, err
			}

			buff := bBytes[offset : offset+10]
			sysId, err := CheckBytes(buff)
			var hook_err MayBeHookedError

			if errors.As(err, &hook_err) {

				// Enter here if function seems to be hooked
				start, size := GetNtdllStart()

				// Search forward
				distanceNeighbor := 0
				for i := uintptr(offset); i < start+size; i += 1 {
					if bBytes[i] == byte('\x0f') && bBytes[i+1] == byte('\x05') && bBytes[i+2] == byte('\xc3') {
						distanceNeighbor++

            sysId, err := CheckBytes(bBytes[i+14 : i+14+8]) // Check hook again
						if !errors.As(err, &hook_err) {                 // Return syscall ID if it isn't hooked
							return sysId - uint16(distanceNeighbor), err
						}
					}
				}

				// Search backward
				distanceNeighbor = 1
				for i := uintptr(offset) - 1; i > 0; i -= 1 {
					if bBytes[i] == byte('\x0f') && bBytes[i+1] == byte('\x05') && bBytes[i+2] == byte('\xc3') {
						distanceNeighbor++

						sysId, err := CheckBytes(bBytes[i+14 : i+14+8])
						if !errors.As(err, &hook_err) { // Return syscall ID if it isn't hooked
							return sysId + uint16(distanceNeighbor) - 1, err
						}
					}
				}
			} else {
				// Return syscall id as it isn't hooked
				return sysId, nil
			}
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
		if strings.ToLower(funcname) == strings.ToLower(exp.Name) {

			offset := rvaToOffset(ntdll_pe, exp.VirtualAddress)
			bBytes, err := ntdll_pe.Bytes()
			if err != nil {
				return 0, err
			}

			buff := bBytes[offset : offset+10]
			sysId, err := CheckBytes(buff)
			var hook_err MayBeHookedError

			if errors.As(err, &hook_err) {

				// Enter here if function seems to be hooked
				start, size := GetNtdllStart()

				// Search forward
				distanceNeighbor := 0
				for i := uintptr(offset); i < start+size; i += 1 {
					if bBytes[i] == byte('\x0f') && bBytes[i+1] == byte('\x05') && bBytes[i+2] == byte('\xc3') {
						distanceNeighbor++

						sysId, err := CheckBytes(bBytes[i+14 : i+14+8]) // Check hook again
						if !errors.As(err, &hook_err) {                 // Return syscall ID if it isn't hooked
							return sysId - uint16(distanceNeighbor), err
						}
					}
				}

				// Search backward
				distanceNeighbor = 1
				for i := uintptr(offset) - 1; i > 0; i -= 1 {
					if bBytes[i] == byte('\x0f') && bBytes[i+1] == byte('\x05') && bBytes[i+2] == byte('\xc3') {
						distanceNeighbor++

						sysId, err := CheckBytes(bBytes[i+14 : i+14+8])
						if !errors.As(err, &hook_err) { // Return syscall ID if it isn't hooked
							return sysId + uint16(distanceNeighbor) - 1, err
						}
					}
				}

			} else {
				// Return syscall id as it isn't hooked
				return sysId, nil
			}
		}
	}

	return 0, errors.New("syscall ID not found")
}
