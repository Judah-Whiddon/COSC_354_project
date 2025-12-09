package main

import "fmt"

// RoutineID: simple label for which implementation is active
type RoutineID string

const (
	RoutineOriginal RoutineID = "original"
	RoutinePatched  RoutineID = "patched"
)

// IntegrityManager: tracks what routine *should* be active vs what actually is
type IntegrityManager struct {
	Expected RoutineID
	Current  RoutineID
}

// KernelAuthority: holds integrity state for the routine
type KernelAuthority struct {
	Integrity *IntegrityManager
}

// NewKernelAuthority: start with the original routine active
func NewKernelAuthority() *KernelAuthority {
	return &KernelAuthority{
		Integrity: &IntegrityManager{
			Expected: RoutineOriginal,
			Current:  RoutineOriginal,
		},
	}
}

// PatchRoutine: simulate inline patching by flipping Current to patched
func (k *KernelAuthority) PatchRoutine() {
	k.Integrity.Current = RoutinePatched
}

// CallIntegrityRoutine: what the caller "sees" when it uses the routine
func (k *KernelAuthority) CallIntegrityRoutine() string {
	if k.Integrity.Current == RoutineOriginal {
		return "WARNING: tampering detected"
	}
	return "OK: no issues detected"
}

// Auditor: checks if the active routine matches the expected one
type Auditor struct {
	kernel *KernelAuthority
}

func NewAuditor(k *KernelAuthority) *Auditor {
	return &Auditor{kernel: k}
}

func (a *Auditor) CheckRoutine() {
	exp := a.kernel.Integrity.Expected
	cur := a.kernel.Integrity.Current

	fmt.Println("=== Routine Integrity Audit ===")
	fmt.Println("Expected routine:", exp)
	fmt.Println("Current routine :", cur)

	if exp != cur {
		fmt.Println("Status: MISMATCH (routine appears to be patched)")
	} else {
		fmt.Println("Status: OK (routine matches expected)")
	}
}

func main() {
	kernel := NewKernelAuthority()

	fmt.Println("=== Before patch ===")
	fmt.Println("Integrity routine output:", kernel.CallIntegrityRoutine())

	auditor := NewAuditor(kernel)
	auditor.CheckRoutine()

	// simulate an inline patch that swaps the routine
	kernel.PatchRoutine()

	fmt.Println("\n=== After patch (simulated inline hook) ===")
	fmt.Println("Integrity routine output:", kernel.CallIntegrityRoutine())

	auditor.CheckRoutine()
}
