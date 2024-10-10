package hooka

import (
  "github.com/D3Ext/Hooka/evasion"
)

func BlockDLLs() error {
  return evasion.BlockDLLs()
}

func CreateProcessBlockDLLs(cmd string) error {
  return evasion.CreateProcessBlockDLLs(cmd)
}

