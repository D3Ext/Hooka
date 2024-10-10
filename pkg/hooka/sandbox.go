package hooka

import "github.com/D3Ext/Hooka/evasion"

func AutoCheck() (bool, error) {
	return evasion.AutoCheck()
}

func CheckMemory() (bool, error) {
	return evasion.CheckMemory()
}

func CheckDisk() (bool, error) {
	return evasion.CheckDisk()
}

func CheckInternet() bool {
	return evasion.CheckInternet()
}

func CheckHostname() (bool, error) {
	return evasion.CheckHostname()
}

func CheckUsername() (bool, error) {
	return evasion.CheckUsername()
}

func CheckCpu() bool {
	return evasion.CheckCpu()
}

func CheckDrivers() bool {
	return evasion.CheckDrivers()
}

func CheckProcess() (bool, error) {
	return evasion.CheckProcess()
}
