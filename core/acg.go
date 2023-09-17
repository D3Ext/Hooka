package core

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

/*
typedef struct _PROCESS_MITIGATION_DYNAMIC_CODE_POLICY {
  union {
    DWORD Flags;
    struct {
      DWORD ProhibitDynamicCode : 1;
      DWORD AllowThreadOptOut : 1;
      DWORD AllowRemoteDowngrade : 1;
      DWORD AuditProhibitDynamicCode : 1;
      DWORD ReservedFlags : 28;
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME;
} PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, *PPROCESS_MITIGATION_DYNAMIC_CODE_POLICY;
*/

type PROCESS_MITIGATION_DYNAMIC_CODE_POLICY struct {
	ProhibitDynamicCode uint32
}

func EnableACG() error {
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	SetProcessMitigationPolicy := kernel32.NewProc("SetProcessMitigationPolicy")

	var ProcessDynamicCodePolicy int32 = 2
	var dcp PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
	dcp.ProhibitDynamicCode = 1

	ret, _, err := SetProcessMitigationPolicy.Call(
		uintptr(ProcessDynamicCodePolicy),
		uintptr(unsafe.Pointer(&dcp)),
		unsafe.Sizeof(dcp),
	)

	if ret != 1 {
		return errors.New(fmt.Sprintf("error: %s\nSetProcessMitigationPolicy returned %x", err, ret))
	}

	return nil
}
