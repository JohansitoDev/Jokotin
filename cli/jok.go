package main

import (
	"fmt"
	"os"

	"jokotin/compiler"
)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "Uso: jok run <archivo.jok>")
		os.Exit(2)
	}

	filename := os.Args[2]
	if err := compiler.RunJokFile(filename); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
