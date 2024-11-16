package evasion

import (
	"errors"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	mproc "github.com/D3Ext/maldev/src/process"
)

func AutoCheck() (bool, error) {
	mem_check, err := CheckMemory()
	if err != nil {
		return false, err
	}

	if mem_check {
    return true, nil
	}

	drivers_check := CheckDrivers()
	if drivers_check {
    return true, nil
	}

	proc_check, err := CheckProcess()
	if err != nil {
		return false, err
	}

	if proc_check {
    return true, nil
	}

	disk_check, err := CheckDisk()
	if err != nil {
		return false, err
	}

	if disk_check {
    return true, nil
	}

	internet_check := CheckInternet()
	if internet_check {
    return true, nil
	}

	hostn_check, err := CheckHostname()
	if err != nil {
		return false, err
	}

	if hostn_check {
    return true, nil
	}

	user_check, err := CheckUsername()
	if err != nil {
    return false, err
	}

	if user_check {
    return true, nil
	}

	cpu_check := CheckCpu()
	if cpu_check {
    return true, nil
	}

	return false, nil
}

func CheckMemory() (bool, error) {
	procGlobalMemoryStatusEx := windows.NewLazyDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

	msx := &memStatusEx{
		dwLength: 64,
	}

	r1, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(msx)))
	if r1 == 0 {
		return false, errors.New("An error has occurred while executing GlobalMemoryStatusEx")
	}

	if msx.ullTotalPhys < 4174967296 {
		return true, nil // May be a sandbox
	} else {
		return false, nil // Not a sandbox
	}
}

func CheckDisk() (bool, error) {
	procGetDiskFreeSpaceExW := windows.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

	lpTotalNumberOfBytes := int64(0)
	diskret, _, err := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("C:\\"))),
		uintptr(0),
		uintptr(unsafe.Pointer(&lpTotalNumberOfBytes)),
		uintptr(0),
	)

	if diskret == 0 {
		return false, err
	}

	if lpTotalNumberOfBytes < 68719476736 {
		return true, nil
	} else {
		return false, nil
	}
}

func CheckInternet() bool {
	client := http.Client{
		Timeout: 3000 * time.Millisecond, // 3s timeout (more than necessary)
	}

	_, err := client.Get("https://google.com")

	if err != nil {
		return true // May be a sandbox
	}

	return false // Not a sandbox
}

func CheckHostname() (bool, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return false, err
	}

	for _, hostname_to_check := range hostnames_list {
		if hostname == hostname_to_check {
			return true, nil // Probably a sandbox
		}
	}

	return false, nil // Not a sandbox
}

func CheckUsername() (bool, error) {
	u, err := user.Current()
	if err != nil {
		return false, err
	}

	for _, username_to_check := range usernames_list {
		if u.Username == username_to_check {
			return true, nil // Probably a sandbox
		}
	}

	return false, nil // Not a sandbox
}

func CheckCpu() bool {
	if runtime.NumCPU() <= 2 {
		return true // Probably a sandbox
	} else {
		return false // Not a sandbox
	}
}

func CheckDrivers() bool {
	for _, d := range drivers { // Iterate over all drivers to check if they exist
		_, err := os.Stat(d)
		if !os.IsNotExist(err) {
			return true // Probably a sandbox
		}
	}

	return false // Not a sandbox
}

func CheckProcess() (bool, error) {
	processes_list, err := mproc.GetProcesses() // Get list of all processes
	if err != nil {
		return false, err
	}

	// Check if at least a quite good amount of processes are running
	if len(processes_list) <= 15 {
		return true, nil // Probably a sandbox
	}

	for _, p := range processes_list {
		for _, p_name := range processes { // Iterate over known VM and sandboxing processes names
			if p.Exe == p_name { // Name matches!
				return true, nil // Probably a sandbox
			}
		}
	}

	return false, nil // Not a sandbox
}
