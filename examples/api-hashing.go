package main

import (
	"crypto/sha1"
	"fmt"
	"github.com/D3Ext/Hooka/pkg/hooka"
	"log"
)

// Convert string to SHA1 (used for hashing)
func Sha1(str string) string {
	h := sha1.New()
	h.Write([]byte(str))
	bs := h.Sum(nil)

	return fmt.Sprintf("%x", bs)
}

func main() {
	hash := "b4de6817d3b22d785568d6480b613c4b2520729a" // Sha1("GetCurrentProcess")

	GetCurrentProcess, _, err := hooka.GetFuncPtr(hash, "C:\\Windows\\System32\\kernel32.dll", Sha1)
	if err != nil {
		log.Fatal(err)
	}

  pHandle, _, _ := GetCurrentProcess.Call()
  fmt.Println("[+] Current process:", pHandle)
}
