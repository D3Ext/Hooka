package hooka

import "github.com/D3Ext/Hooka/core"

/*

Functions which inject shellcode without Hell's Gate + Halo's Gate

*/

func CreateRemoteThread(shellcode []byte) (error) {
  return core.CreateRemoteThread(shellcode)
}

func CreateProcess(shellcode []byte) (error) {
  return core.CreateProcess(shellcode)
}

func Fibers(shellcode []byte) (error) {
  return core.Fibers(shellcode)
}

func EarlyBirdApc(shellcode []byte) (error) {
  return core.EarlyBirdApc(shellcode)
}

/*func QueueApcThread(shellcode []byte) (error) {
  return core.QueueApcThread(shellcode)
}*/

func UuidFromString(shellcode []byte) (error) {
  return core.UuidFromString(shellcode)
}

/*

Hell's Gate + Halo's Gate functions (WIP)

*/

func CreateProcessHalos(shellcode []byte) (error) {
  return core.CreateProcessHalos(shellcode)
}

func CreateRemoteThreadHalos(shellcode []byte) (error) {
  return core.CreateRemoteThreadHalos(shellcode)
}

