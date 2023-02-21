package hooka

import "github.com/D3Ext/Hooka/core"

func ClassicUnhook(funcname string, dllpath string) (error) {
  return core.Unhook(funcname, dllpath)
}

func FullUnhook(funcname string) (error) {
  return core.FullUnhook(funcname)
}

func PerunsUnhook() (error) {
  return core.PerunsUnhook()
}


