package hooka

import "github.com/D3Ext/Hooka/evasion"

func PatchEtw() error {
	return evasion.PatchEtw()
}

func PatchEtw2() error {
	return evasion.PatchEtw2()
}
