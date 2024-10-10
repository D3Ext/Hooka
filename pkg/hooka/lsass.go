package hooka

import "github.com/D3Ext/Hooka/evasion"

func DumpLsass(output_file string) error {
	return evasion.DumpLsass(output_file)
}
