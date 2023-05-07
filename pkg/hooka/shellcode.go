package hooka

import "github.com/D3Ext/Hooka/core"

/*

Functions which inject shellcode without Hell's Gate + Halo's Gate

*/

func CreateRemoteThread(shellcode []byte, pid int) (error) {
  return core.CreateRemoteThread(shellcode, pid)
}

func CreateProcess(shellcode []byte, pid int) (error) {
  return core.CreateProcess(shellcode, pid)
}

func EnumSystemLocales(shellcode []byte) (error) {
  return core.EnumSystemLocales(shellcode)
}

func Fibers(shellcode []byte) (error) {
  return core.Fibers(shellcode)
}

func QueueUserApc(shellcode []byte) (error) {
  return core.QueueUserApc(shellcode)
}

func UuidFromString(shellcode []byte) (error) {
  return core.UuidFromString(shellcode)
}

func EtwpCreateEtwThread(shellcode []byte) (error) {
  return core.EtwpCreateEtwThread(shellcode)
}

/*

Hell's Gate + Halo's Gate functions (WIP)

*/

func CreateRemoteThreadHalos(shellcode []byte) (error) {
  return core.CreateRemoteThreadHalos(shellcode)
}

func EnumSystemLocalesHalos(shellcode []byte) (error) {
  return core.EnumSystemLocalesHalos(shellcode)
}

