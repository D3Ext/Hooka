package hooka

import "github.com/D3Ext/Hooka/evasion"

func GetEventLogPid() (int, error) {
	return evasion.GetEventLogPid()
}

func Phant0m(eventlog_pid int) error {
	return evasion.Phant0m(eventlog_pid)
}

