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

func Fibers(shellcode []byte, pid int) (error) {
  return core.Fibers(shellcode, pid)
}

func EarlyBirdApc(shellcode []byte, pid int) (error) {
  return core.EarlyBirdApc(shellcode, pid)
}

func UuidFromString(shellcode []byte, pid int) (error) {
  return core.UuidFromString(shellcode, pid)
}

/*

Hell's Gate + Halo's Gate functions (WIP)

*/

func CreateProcessHalos(shellcode []byte, pid int) (error) {
  return core.CreateProcessHalos(shellcode, pid)
}

func CreateRemoteThreadHalos(shellcode []byte, pid int) (error) {
  return core.CreateRemoteThreadHalos(shellcode, pid)
}

