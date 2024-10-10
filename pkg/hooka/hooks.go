package hooka

import (
	"github.com/D3Ext/Hooka/evasion"
)

func DetectHooks() ([]string, error) {
	return evasion.DetectHooks()
}

func IsHooked(func_name string) (bool, error) {
	return evasion.IsHooked(func_name)
}
