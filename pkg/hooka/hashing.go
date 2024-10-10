package hooka

import (
  "github.com/D3Ext/Hooka/utils"
  "github.com/D3Ext/Hooka/evasion"
  "golang.org/x/sys/windows"
)

func GetFuncPtr(hash string, dll string, hashing_func func(str string) string) (*windows.LazyProc, string, error) {
  return evasion.GetFuncPtr(hash, dll, hashing_func)
}

func GetSysIdHash(hash string, dll string, hashing_func func(str string) string) (uint16, string, error) {
	return evasion.GetSysIdHash(hash, dll, hashing_func)
}

func GetSysIdHashHalos(hash string, hashing_func func(str string) string) (uint16, string, error) {
	return evasion.GetSysIdHashHalos(hash, hashing_func)
}

func Md5(src string) string {
  return utils.Md5(src)
}

func Sha1(src string) string {
  return utils.Sha1(src)
}

func Sha256(src string) string {
  return utils.Sha256(src)
}

