package hooka

import "github.com/D3Ext/Hooka/core"

func Inject(shellcode []byte, technique string, pid int) (error) {
  return core.Inject(shellcode, technique, pid)
}

