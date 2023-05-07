package hooka

import "github.com/D3Ext/Hooka/core"

func GetEventLogPid() (uint32, error) {
  return core.GetEventLogPid()
}

func Phant0m(pid uint32) (error) {
  return core.Phant0m(pid)
}

func Phant0mWithOutput(pid uint32) (error) {
  return core.Phant0mWithOutput(pid)
}



