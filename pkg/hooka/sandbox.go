package hooka

import "github.com/D3Ext/Hooka/core"

func AutoCheck() error {
	return core.AutoCheck()
}

func CheckMemory() (bool, error) {
	return core.CheckMemory()
}

func CheckDisk() (bool, error) {
	return core.CheckDisk()
}

func CheckInternet() bool {
	return core.CheckInternet()
}

func CheckHostname() (bool, error) {
	return core.CheckHostname()
}

func CheckUsername() (bool, error) {
	return core.CheckUsername()
}

func CheckCpu() bool {
	return core.CheckCpu()
}

func CheckDrivers() bool {
	return core.CheckDrivers()
}

func CheckProcess() (bool, error) {
	return core.CheckProcess()
}
