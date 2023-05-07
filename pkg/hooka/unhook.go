package hooka

import "github.com/D3Ext/Hooka/core"

func ClassicUnhook(funcnames []string, dllpath string) (error) {
  return core.ClassicUnhook(funcnames, dllpath)
}

func FullUnhook(dllpath string) (error) {
  return core.FullUnhook(dllpath)
}

func PerunsUnhook() (error) {
  return core.PerunsUnhook()
}


