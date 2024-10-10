package utils

import (
  "golang.org/x/sys/windows"
)

func CheckHighPrivs() (bool, error) { // Function to check if current user has Administrator privileges
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false, err
	}

	token := windows.Token(0)
	member, err := token.IsMember(sid) // Check if is inside admin group
	if err != nil {
		return false, err
	}

	return member, nil // return true (means high privs) or false (means low privs)
}
