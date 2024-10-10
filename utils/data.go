package utils

import (
  "slices"
)

func AppendString(slice []string, str string) []string {
  if (!slices.Contains(slice, str)) {
    slice = append(slice, str)
  }

  return slice
}

func AppendSlice(slice, slice2 []string) []string {
  for _, entry := range slice2 {
    if (!slices.Contains(slice, entry)) {
      slice = append(slice, entry)
    }
  }

  return slice
}

