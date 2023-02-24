package hooka

import "github.com/D3Ext/Hooka/core"

func ClassicUnhook(funcname string, dllpath string) (error) {
  return core.Unhook(funcname, dllpath)
}

func FullUnhook(dllpath string) (error) {
  return core.FullUnhook(dllpath)
}

func PerunsUnhook() (error) {
  return core.PerunsUnhook()
}


