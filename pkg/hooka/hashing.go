package hooka

import "github.com/D3Ext/Hooka/core"

func FuncFromHash(hash string, dll string) (uint16, string, error) {
  return core.FuncFromHash(hash, dll)
}

func HashFromFunc(funcname string) (string) {
  return core.HashFromFunc(funcname)
}


