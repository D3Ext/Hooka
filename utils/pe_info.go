package utils

import (
  "os"
  "log"
  "math"
  "io"
  "fmt"
  "crypto/md5"
  "crypto/sha1"
  "crypto/sha256"
  "io/ioutil"
)

func Entropy(file string) (float64, error) {
  f, err := os.Open(file)
  if err != nil {
    return 0, err
  }
  defer f.Close()

  contents, err := ioutil.ReadAll(f)
  if err != nil {
    return 0, err
  }

  freq := make(map[byte]int)
  for _, b := range contents {
    freq[b]++
  }

  totalBytes := len(contents)
  probs := make(map[byte]float64)
  for b, f := range freq {
    probs[b] = float64(f) / float64(totalBytes)
  }

  entropy := 0.0
  for _, p := range probs {
    if p > 0 {
      entropy -= p * math.Log2(p)
    }
  }

  return entropy, nil
}

func CalculateSums(output_file string) (string, string, string, error) {
  f1, err := os.Open(output_file)
  if err != nil {
    return "", "", "", err
  }
  defer f1.Close()

  md5hash := md5.New()
  _, err = io.Copy(md5hash, f1)
  if err != nil {
    return "", "", "", err
  }

  f2, err := os.Open(output_file)
  if err != nil {
    return "", "", "", err
  }
  defer f2.Close()

  sha256hash := sha256.New()
  _, err = io.Copy(sha256hash, f2)
  if err != nil {
    return "", "", "", err
  }

  f3, err := os.Open(output_file)
  if err != nil {
    return "", "", "", err
  }
  defer f3.Close()

  sha1hash := sha1.New()
  _, err = io.Copy(sha1hash, f3)
  if err != nil {
    log.Fatal(err)
  }

  return fmt.Sprintf("%x", md5hash.Sum(nil)), fmt.Sprintf("%x", sha1hash.Sum(nil)), fmt.Sprintf("%x", sha256hash.Sum(nil)), nil
}

