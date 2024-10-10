package hooka

import "github.com/D3Ext/Hooka/evasion"

func GetSysId(funcname string) (uint16, error) {
	return evasion.GetSysId(funcname)
}

