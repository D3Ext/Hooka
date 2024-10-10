package evasion

import "fmt"

func Syscall(callid uint16, argh ...uintptr) (errcode uint32, err error) {
	errcode = bpSyscall(callid, argh...)

	if errcode != 0 {
		err = fmt.Errorf("non-zero return from syscall")
	}

	return errcode, err
}

func bpSyscall(callid uint16, argh ...uintptr) (errcode uint32)


