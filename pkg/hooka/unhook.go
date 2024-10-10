package hooka

import "github.com/D3Ext/Hooka/evasion"

func ClassicUnhook(funcnames []string, dllpath string) error {
	return evasion.ClassicUnhook(funcnames, dllpath)
}

// unhook especified DLLs (provide full paths)
func FullUnhook(dlls_to_unhook []string) error {
	return evasion.FullUnhook(dlls_to_unhook)
}

// unhook ntdll.dll
func PerunsUnhook() error {
	return evasion.PerunsUnhook()
}
