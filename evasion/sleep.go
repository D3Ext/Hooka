package evasion

func Sleep() {
  s := 500000

  for i := 0; i <= s; i++ {
    for j := 2; j <= i/2; j++ {
      if i % j == 0 {
        break
      }
    }
  }
}
