package hooka

import (
  "github.com/D3Ext/Hooka/core"
)

func DetectHooks() ([]string, error) {
  return core.DetectHooks()
}

func IsHooked(func_name string) (bool, error) {
  return core.IsHooked(func_name)
}

