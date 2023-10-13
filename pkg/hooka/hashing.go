package hooka

import "github.com/D3Ext/Hooka/core"

func FuncFromHash(hash string, dll string, hashing_func func(string) string) (uint16, string, error) {
	return core.FuncFromHash(hash, dll, hashing_func)
}

func HalosFuncFromHash(hash string, hashing_func func(str string) string) (uint16, string, error) {
	return core.GetSysIdHashing(hash, hashing_func)
}
