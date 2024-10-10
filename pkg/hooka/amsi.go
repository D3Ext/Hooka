package hooka

import "github.com/D3Ext/Hooka/evasion"

func PatchAmsi() error {
	return evasion.PatchAmsi()
}

func PatchAmsi2() error {
	return evasion.PatchAmsi2()
}
