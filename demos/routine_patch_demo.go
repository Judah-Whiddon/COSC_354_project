package main

import "fmt"

// CheckIntegrity: function variable that stands in for a kernel routine
var CheckIntegrity func() string

// honestRoutine: what the routine is supposed to return
func honestRoutine() string {
	return "WARNING: tampering detected"
}

// patchedRoutine: attacker-controlled version of the same routine
func patchedRoutine() string {
	return "OK: no issues detected"
}

func main() {
	// before patch: caller uses the original routine
	CheckIntegrity = honestRoutine
	fmt.Println("=== Before patch (original routine) ===")
	fmt.Println("CheckIntegrity():", CheckIntegrity())

	// "inline patch": swap the function pointer to the attacker version
	CheckIntegrity = patchedRoutine
	fmt.Println("\n=== After patch (simulated inline hook) ===")
	fmt.Println("CheckIntegrity():", CheckIntegrity())
}
