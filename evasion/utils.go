package evasion

import (
  "encoding/binary"
  "bytes"
  "unsafe"
  "syscall"
  "strings"
  "fmt"
  "crypto/sha1"
  //"golang.org/x/sys/windows"
  "github.com/Binject/debug/pe"
)

func Sha1(str string) string {
    h := sha1.New()
    h.Write([]byte(str))
    bs := h.Sum(nil)

    return fmt.Sprintf("%x", bs)
}

var HookCheck = []byte{0x4c, 0x8b, 0xd1, 0xb8} // Define hooked bytes to look for

type MayBeHookedError struct { // Define custom error for hooked functions
	Foundbytes []byte
}

func (e MayBeHookedError) Error() string {
	return fmt.Sprintf("may be hooked: wanted %x got %x", HookCheck, e.Foundbytes)
}

func CheckBytes(b []byte) (uint16, error) {
	if !bytes.HasPrefix(b, HookCheck) { // Check syscall bytes
		return 0, MayBeHookedError{Foundbytes: b}
	}

	return binary.LittleEndian.Uint16(b[4:8]), nil
}

// getString extracts a string from symbol string table.
func getString(section []byte, start int) (string, bool) {
	if start < 0 || start >= len(section) {
		return "", false
	}

	for end := start; end < len(section); end++ {
		if section[end] == 0 {
			return string(section[start:end]), true
		}
	}
	return "", false
}

func rvaToOffset(pefile *pe.File, rva uint32) uint32 {
	for _, hdr := range pefile.Sections {
		baseoffset := uint64(rva)
		if baseoffset > uint64(hdr.VirtualAddress) &&
			baseoffset < uint64(hdr.VirtualAddress+hdr.VirtualSize) {
			return rva - hdr.VirtualAddress + hdr.Offset
		}
	}
	return rva
}

func inMemLoads(modulename string) (uintptr, uintptr) {
	s, si, p := gMLO(0)
	start := p
	i := 1

	if strings.Contains(strings.ToLower(p), strings.ToLower(modulename)) {
		return s, si
	}

	for {
		s, si, p = gMLO(i)

		if p != "" {
			if strings.Contains(strings.ToLower(p), strings.ToLower(modulename)) {
				return s, si
			}
		}

		if p == start {
			break
		}

		i++
	}

	return 0, 0
}

func GetNtdllStart() (start uintptr, size uintptr)

func gMLO(i int) (start uintptr, size uintptr, modulepath string) {
	var badstring *sstring
	start, size, badstring = getMLO(i)
	modulepath = badstring.String()
	return
}

// getModuleLoadedOrder returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func getMLO(i int) (start uintptr, size uintptr, modulepath *sstring)

// Enable SeDebugPrivilege
func ElevateProcessToken() error {

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

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	advapi32 := syscall.NewLazyDLL("advapi32.dll")

	GetCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	GetLastError := kernel32.NewProc("GetLastError")
	OpenProcessToken := advapi32.NewProc("OpenProcessToken")
	LookupPrivilegeValue := advapi32.NewProc("LookupPrivilegeValueW")
	AdjustTokenPrivileges := advapi32.NewProc("AdjustTokenPrivileges")

	currentProcess, _, _ := GetCurrentProcess.Call()

	result, _, err := OpenProcessToken.Call(
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

