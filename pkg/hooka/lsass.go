package hooka

import "github.com/D3Ext/Hooka/core"

func DumpLsass(output string) (error) {
  return core.DumpLsass(output)
}

func EnableSeDebug() (error) {
  return core.ElevateProcessToken()
}

