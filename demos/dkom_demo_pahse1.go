package main

import "fmt"

// Process: minimal stand-in for a kernel process object
type Process struct {
    Name    string
    PID     int
    Running bool
}

func printList(label string, procs []Process) {
    fmt.Println(label)
    for _, p := range procs {
        fmt.Printf("  PID %d  %-10s  running=%v\n", p.PID, p.Name, p.Running)
    }
    fmt.Println()
}

func main() {
    // executionTable: what is actually running in the system
    executionTable := []Process{
        {"system", 1, true},
        {"svchost", 2, true},
        {"malicious", 3, true},
        {"explorer", 4, true},
    }

    // visibleTable: what user-mode enumeration APIs return
    visibleTable := make([]Process, len(executionTable))
    copy(visibleTable, executionTable)

    fmt.Println("=== Before DKOM (no manipulation) ===")
    printList("Execution table (kernel truth):", executionTable)
    printList("Visible table   (user view)   :", visibleTable)

    // --- DKOM attack: unlink "malicious" from the visible list only ---
    filtered := []Process{}
    for _, p := range visibleTable {
        if p.Name == "malicious" {
            // stays running, just removed from the list
            continue
        }
        filtered = append(filtered, p)
    }
    visibleTable = filtered

    fmt.Println("=== After DKOM (process unlinked from visible list) ===")
    printList("Execution table (kernel truth):", executionTable)
    printList("Visible table   (user view)   :", visibleTable)
}
