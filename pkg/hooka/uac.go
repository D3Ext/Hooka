package hooka

import "github.com/D3Ext/Hooka/core"

func ExecUac(path string) (error) {
  return core.ExecUac(path)
}

func RemoveUacFiles() (error) {
  return core.RemoveUacFiles()
}

/*func SelfExecUac() (error) {
  return core.SelfExecUac()
}*/


