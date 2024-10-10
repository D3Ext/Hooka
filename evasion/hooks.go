package evasion

/*

References:
https://www.ired.team/offensive-security/defense-evasion/detecting-hooked-syscall-functions

*/

import (
	"bytes"
	"strings"

	// Third-party packages
	"github.com/Binject/debug/pe"
)

func DetectHooks() ([]string, error) {
	var hooked_functions []string

	dll_pe, err := pe.Open(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}))
	if err != nil {
		return hooked_functions, err
	}
	defer dll_pe.Close()

	exports, err := dll_pe.Exports() // Get exported functions
	if err != nil {
		return hooked_functions, err
	}

	for _, exp := range exports { // Iterate over them

		offset := rvaToOffset(dll_pe, exp.VirtualAddress) // Get RVA offset
		bBytes, err := dll_pe.Bytes()                     // Get bytes from ntdll.dll
		if err != nil {
			return hooked_functions, err
		}

		buff := bBytes[offset : offset+10]

		if len(exp.Name) > 3 { // Avoid errors by checking function name length
			if exp.Name[0:2] == "Nt" || exp.Name[0:2] == "Zw" { // Just use functions which start by "Nt" or "Zw"
        if !bytes.HasPrefix(buff, HookCheck) { // check if it is hooked
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
		if strings.ToLower(funcname) == strings.ToLower(h) {
			return true, nil
		}
	}

	return false, nil
}
