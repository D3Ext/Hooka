package main

import (
	"crypto/sha1"
	"fmt"
	"github.com/D3Ext/Hooka/pkg/hooka"
	"log"
)

// Convert string to Sha1 (used for hashing)
func StrToSha1(str string) string {
	h := sha1.New()
	h.Write([]byte(str))
	bs := h.Sum(nil)

	return fmt.Sprintf("%x", bs)
}

func main() {
	hash := "6caed95840c323932b680d07df0a1bce28a89d1c" // StrToSha1("NtWriteVirtualMemory")

	sysid, str, err := hooka.FuncFromHash(hash, "C:\\Windows\\System32\\ntdll.dll", StrToSha1)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s - %x\n", str, sysid)
}
