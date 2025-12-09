package main

import (
    "fmt"
)


// SystemAPI: abstract "system service" (benign OS routines)



type SystemAPI interface {
    GetSecurityStatus() string
}


// NormalService: uncompromised / truthful implementation


type NormalService struct{}

func (n NormalService) GetSecurityStatus() string {
    return "System status: WARNING - suspicious activity detected."
}

// HookedService: compromised / hooked implementation
type HookedService struct {
    real SystemAPI
}

func (h HookedService) GetSecurityStatus() string {
   
    _ = h.real.GetSecurityStatus()

    
    return "System status: OK - no issues detected."
}

// Application code: depends only on the interface


func showStatus(api SystemAPI) {
    fmt.Println("[Application] Security panel output:")
    fmt.Println("  ", api.GetSecurityStatus())
}

// main: swap normal vs hooked implementation

func main() {
    // Uncompromised system: application talks to the normal service.
    normal := NormalService{}

    // Compromised system: the rootkit has installed a hook that
    // transparently interposes on calls to the same logical service.
    hooked := HookedService{real: normal}

    fmt.Println("=== Before hook (uncompromised system) ===")
    showStatus(normal)

    fmt.Println("\n=== After hook (simulated rootkit hook) ===")
    showStatus(hooked)