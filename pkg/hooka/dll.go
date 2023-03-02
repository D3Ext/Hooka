package hooka

import "github.com/D3Ext/Hooka/core"

func ConvertDllToShellcode(dll_file string, dll_func string, func_args string) ([]byte, error) {
  return core.ConvertDllToShellcode(dll_file, dll_func, func_args)
}

func ConvertDllBytesToShellcode(dll_bytes []byte, dll_func string, func_args string) ([]byte, error) {
  return core.ConvertDllBytesToShellcode(dll_bytes, dll_func, func_args)
}

