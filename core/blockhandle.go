package core

import (
	"time"
	//"errors"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

func ConvertStringSecurityDescriptorToSecurityDescriptorW(p1 uintptr, p2 uintptr, p3 uintptr, p4 uintptr) error {
	advapi32 := windows.NewLazySystemDLL("advapi32.dll")
	procConvertStringSecurityDescriptorToSecurityDescriptorW := advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")

	r, _, _ := syscall.Syscall6(
		procConvertStringSecurityDescriptorToSecurityDescriptorW.Addr(),
		4,
		uintptr(p1),
		uintptr(p2),
		uintptr(p3),
		uintptr(p4),
		0,
		0,
	)
	if r != 0 {
		return syscall.Errno(r)
	}

	return nil
}

func BlockHandle() error {
	sddl, _ := syscall.UTF16PtrFromString("D:P(D;OICI;GA;;;WD)(A;OICI;GA;;;SY)(A;OICI;GA;;;OW)")
	var sec_descriptor *windows.SECURITY_DESCRIPTOR = nil

	ConvertStringSecurityDescriptorToSecurityDescriptorW(
		uintptr(unsafe.Pointer(sddl)),
		1,
		uintptr(unsafe.Pointer(sec_descriptor)),
		0,
	)

	windows.SetKernelObjectSecurity(
		windows.CurrentProcess(),
		windows.DACL_SECURITY_INFORMATION,
		sec_descriptor,
	)

	sec := uintptr(unsafe.Pointer(sec_descriptor))
	windows.LocalFree(windows.Handle(sec))
	time.Sleep(10000 * time.Second)

	return nil
}
