package main

import "fmt"

// Process: simple representation of a kernel process entry
type Process struct {
    Name    string
    PID     int
    Running bool
}

// KernelAuthority: maintains the real execution table and the visible process list
type KernelAuthority struct {
    executionTable []Process
    visibleTable   []Process
}

func NewKernelAuthority() *KernelAuthority {
    exec := []Process{
        {"system", 1, true},
        {"svchost", 2, true},
        {"malicious", 3, true},
        {"explorer", 4, true},
    }

    vis := make([]Process, len(exec))
    copy(vis, exec)

    return &KernelAuthority{
        executionTable: exec,
        visibleTable:   vis,
    }
}

// DkomHide: simulates removing a process from the visible list only
func (k *KernelAuthority) DkomHide(name string) {
    filtered := []Process{}
    for _, p := range k.visibleTable {
        if p.Name == name {
            continue // unlink from visible list
        }
        filtered = append(filtered, p)
    }
    k.visibleTable = filtered
}

func (k *KernelAuthority) ExecutionView() []Process {
    out := make([]Process, len(k.executionTable))
    copy(out, k.executionTable)
    return out
}

func (k *KernelAuthority) VisibleView() []Process {
    out := make([]Process, len(k.visibleTable))
    copy(out, k.visibleTable)
    return out
}

// Auditor: compares execution vs visible lists to find hidden entries
type Auditor struct {
    kernel *KernelAuthority
}

type DkomDiff struct {
    Execution []Process
    Visible   []Process
    Hidden    []Process
}

func NewAuditor(k *KernelAuthority) *Auditor {
    return &Auditor{kernel: k}
}

func (a *Auditor) Diff() DkomDiff {
    exec := a.kernel.ExecutionView()
    vis := a.kernel.VisibleView()

    execMap := make(map[int]Process)
    for _, p := range exec {
        execMap[p.PID] = p
    }
    for _, p := range vis {
        delete(execMap, p.PID)
    }

    hidden := []Process{}
    for _, p := range execMap {
        hidden = append(hidden, p)
    }

    return DkomDiff{
        Execution: exec,
        Visible:   vis,
        Hidden:    hidden,
    }
}

func printProcs(label string, procs []Process) {
    fmt.Println(label)
    for _, p := range procs {
        fmt.Printf("  PID %d  %-10s  running=%v\n", p.PID, p.Name, p.Running)
    }
    fmt.Println()
}

func main() {
    kernel := NewKernelAuthority()

    // DKOM attack simulation: hide "malicious" from visible list only
    kernel.DkomHide("malicious")

    fmt.Println("=== DKOM Refined Demo ===")
    printProcs("User-visible process list:", kernel.VisibleView())

    auditor := NewAuditor(kernel)
    diff := auditor.Diff()

    fmt.Println("=== Auditor Cross-View Check ===")
    printProcs("Execution table (kernel truth):", diff.Execution)
    printProcs("Visible table   (user view)   :", diff.Visible)
    printProcs("Hidden processes (exec - visible):", diff.Hidden)
}
