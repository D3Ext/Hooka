package hooka

import "github.com/D3Ext/Hooka/core"

func GetSysId(funcname string) (uint16, error) {
  return core.GetSysId(funcname)
}

func GetFuncPtr(funcname string) (uint64, error) {
  return core.GetFuncPtr(funcname)
}

