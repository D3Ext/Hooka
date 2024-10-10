package evasion

var drivers []string = []string{
  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'd', 'r', 'i', 'v', 'e', 'r', 's', '\\', 'V', 'B', 'o', 'x', 'M', 'o', 'u', 's', 'e', '.', 's', 'y', 's'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'd', 'r', 'i', 'v', 'e', 'r', 's', '\\', 'V', 'B', 'o', 'x', 'G', 'u', 'e', 's', 't', '.', 's', 'y', 's'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'd', 'r', 'i', 'v', 'e', 'r', 's', '\\', 'V', 'B', 'o', 'x', 'S', 'F', '.', 's', 'y', 's'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'd', 'r', 'i', 'v', 'e', 'r', 's', '\\', 'V', 'B', 'o', 'x', 'V', 'i', 'd', 'e', 'o', '.', 's', 'y', 's'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'v', 'b', 'o', 'x', 'd', 'i', 's', 'p', '.', 'd', 'l', 'l'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'v', 'b', 'o', 'x', 'h', 'o', 'o', 'k', '.', 'd', 'l', 'l'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'v', 'b', 'o', 'x', 'm', 'r', 'x', 'n', 'p', '.', 'd', 'l', 'l'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'v', 'b', 'o', 'x', 'o', 'g', 'l', '.', 'd', 'l', 'l'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'v', 'b', 'o', 'x', 'o', 'g', 'l', 'a', 'r', 'r', 'a', 'y', 's', 'p', 'u', '.', 'd', 'l', 'l'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'v', 'b', 'o', 'x', 's', 'e', 'r', 'v', 'i', 'c', 'e', '.', 'e', 'x', 'e'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'v', 'b', 'o', 'x', 't', 'r', 'a', 'y', '.', 'e', 'x', 'e'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'V', 'B', 'o', 'x', 'C', 'o', 'n', 't', 'r', 'o', 'l', '.', 'e', 'x', 'e'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'd', 'r', 'i', 'v', 'e', 'r', 's', '\\', 'v', 'm', 'm', 'o', 'u', 's', 'e', '.', 's', 'y', 's'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'd', 'r', 'i', 'v', 'e', 'r', 's', '\\', 'v', 'm', 'h', 'g', 'f', 's', '.', 's', 'y', 's'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'd', 'r', 'i', 'v', 'e', 'r', 's', '\\', 'v', 'm', 'c', 'i', '.', 's', 'y', 's'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'd', 'r', 'i', 'v', 'e', 'r', 's', '\\', 'v', 'm', 'm', 'e', 'm', 'c', 't', 'l', '.', 's', 'y', 's'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'd', 'r', 'i', 'v', 'e', 'r', 's', '\\', 'v', 'm', 'm', 'o', 'u', 's', 'e', '.', 's', 'y', 's'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'd', 'r', 'i', 'v', 'e', 'r', 's', '\\', 'v', 'm', 'r', 'a', 'w', 'd', 's', 'k', '.', 's', 'y', 's'}),

  string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'd', 'r', 'i', 'v', 'e', 'r', 's', '\\', 'v', 'm', 'u', 's', 'b', 'm', 'o', 'u', 's', 'e', '.', 's', 'y', 's'}),
}

var processes []string = []string{ // Sandbox processes taken from https://github.com/LordNoteworthy/al-khaser
  string([]byte{'v', 'b', 'o', 'x', 's', 'e', 'r', 'v', 'i', 'c', 'e', '.', 'e', 'x', 'e'}),
  string([]byte{'v', 'b', 'o', 'x', 't', 'r', 'a', 'y', '.', 'e', 'x', 'e'}),
  string([]byte{'v', 'm', 't', 'o', 'o', 'l', 's', 'd', '.', 'e', 'x', 'e'}),
  string([]byte{'v', 'm', 'w', 'a', 'r', 'e', 't', 'r', 'a', 'y', '.', 'e', 'x', 'e'}),
  string([]byte{'v', 'm', 'w', 'a', 'r', 'e', '.', 'e', 'x', 'e'}),
  string([]byte{'v', 'm', 'w', 'a', 'r', 'e', '-', 'v', 'm', 'x', '.', 'e', 'x', 'e'}),
  string([]byte{'v', 'm', 'w', 'a', 'r', 'e', 'u', 's', 'e', 'r'}),
  string([]byte{'V', 'G', 'A', 'u', 't', 'h', 'S', 'e', 'r', 'v', 'i', 'c', 'e', '.', 'e', 'x', 'e'}),
  string([]byte{'v', 'm', 'a', 'c', 't', 'h', 'l', 'p', '.', 'e', 'x', 'e'}),
  string([]byte{'v', 'm', 's', 'r', 'v', 'c', '.', 'e', 'x', 'e'}),
  string([]byte{'v', 'm', 'u', 's', 'r', 'v', 'c', '.', 'e', 'x', 'e'}),
  string([]byte{'x', 'e', 'n', 's', 'e', 'r', 'v', 'i', 'c', 'e', '.', 'e', 'x', 'e'}),
  string([]byte{'q', 'e', 'm', 'u', '-', 'g', 'a', '.', 'e', 'x', 'e'}),
  string([]byte{'w', 'i', 'r', 'e', 's', 'h', 'a', 'r', 'k', '.', 'e', 'x', 'e'}),
  string([]byte{'P', 'r', 'o', 'c', 'm', 'o', 'n', '.', 'e', 'x', 'e'}),
  string([]byte{'P', 'r', 'o', 'c', 'm', 'o', 'n', '6', '4', '.', 'e', 'x', 'e'}),
  string([]byte{'v', 'o', 'l', 'a', 't', 'i', 'l', 'y', '.', 'e', 'x', 'e'}),
  string([]byte{'v', 'o', 'l', 'a', 't', 'i', 'l', 'y', '3', '.', 'e', 'x', 'e'}),
  string([]byte{'D', 'u', 'm', 'p', 'I', 't', '.', 'e', 'x', 'e'}),
  string([]byte{'d', 'u', 'm', 'p', 'i', 't', '.', 'e', 'x', 'e'}),
}

var hostnames_list []string = []string{
  string([]byte{'S', 'a', 'n', 'd', 'b', 'o', 'x'}),
  string([]byte{'S', 'A', 'N', 'D', 'B', 'O', 'X'}),
  string([]byte{'m', 'a', 'l', 'w', 'a', 'r', 'e'}),
  string([]byte{'v', 'i', 'r', 'u', 's'}),
  string([]byte{'V', 'i', 'r', 'u', 's'}),
  string([]byte{'s', 'a', 'm', 'p', 'l', 'e'}),
  string([]byte{'d', 'e', 'b', 'u', 'g'}),
  string([]byte{'U', 'S', 'E', 'R', '-', 'P', 'C'}),
  string([]byte{'a', 'n', 'a', 'l', 'y', 's', 'i', 's'}),
  string([]byte{'c', 'u', 'c', 'k', 'o', 'o'}),
  string([]byte{'c', 'u', 'c', 'k', 'o', 'o', 'f', 'o', 'r', 'k'}),
  string([]byte{'C', 'u', 'c', 'k', 'o', 'o'}),
}

var usernames_list []string = []string{
  string([]byte{'s', 'a', 'n', 'd', 'b', 'o', 'x'}),
  string([]byte{'v', 'i', 'r', 'u', 's'}),
  string([]byte{'m', 'a', 'l', 'w', 'a', 'r', 'e'}),
  string([]byte{'d', 'e', 'b', 'u', 'g', '4', 'f', 'u', 'n'}),
  string([]byte{'d', 'e', 'b', 'u', 'g'}),
  string([]byte{'s', 'y', 's'}),
  string([]byte{'u', 's', 'e', 'r', '1'}),
  string([]byte{'V', 'i', 'r', 't', 'u', 'a', 'l'}),
  string([]byte{'v', 'i', 'r', 't', 'u', 'a', 'l'}),
  string([]byte{'a', 'n', 'a', 'l', 'y', 'i', 's'}),
  string([]byte{'t', 'r', 'a', 'n', 's', '_', 'i', 's', 'o', '_', '0'}),
  string([]byte{'j', '.', 'y', 'o', 'r', 'o', 'i'}),
  string([]byte{'v', 'e', 'n', 'u', 's', 'e', 'y', 'e'}),
  string([]byte{'V', 'e', 'n', 'u', 's', 'E', 'y', 'e'}),
  string([]byte{'V', 'i', 'r', 'u', 's', 'T', 'o', 't', 'a', 'l'}),
  string([]byte{'v', 'i', 'r', 'u', 's', 't', 'o', 't', 'a', 'l'}),
}
