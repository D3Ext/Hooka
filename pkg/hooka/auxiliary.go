package hooka

import "github.com/D3Ext/Hooka/core"

func GetShellcodeFromUrl(url string) ([]byte, error) {
	return core.GetShellcodeFromUrl(url)
}

func GetShellcodeFromFile(file string) ([]byte, error) {
	return core.GetShellcodeFromFile(file)
}

func CalcShellcode() []byte {
	return core.CalcShellcode()
}

func ElevateProcessToken() error {
	return core.ElevateProcessToken()
}

func CheckHighPrivs() (bool, error) {
	return core.CheckHighPrivs()
}
