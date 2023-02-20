package hooka

import (
  "golang.org/x/sys/windows"

  "github.com/D3Ext/Hooka/core"
)

func FuncFromHash(hash string, dll string) (*windows.LazyProc, string, error) {
  return core.FuncFromHash(hash, dll)
}

func HashFromFunc(funcname string) (string) {
  return core.HashFromFunc(funcname)
}


