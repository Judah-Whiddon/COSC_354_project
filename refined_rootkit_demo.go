package main

import (
	"fmt"
)

// KernelAuthority: holds the real system state (what's actually happening)
type KernelAuthority struct {
	Alerts []string
}

func NewKernelAuthority() *KernelAuthority {
	return &KernelAuthority{
		Alerts: []string{
			"WARNING: suspicious process detected",
			"WARNING: unsigned driver loaded",
			"WARNING: anomalous network activity observed",
		},
	}
}

func (k *KernelAuthority) GetAlerts() []string {
	out := make([]string, len(k.Alerts))
	copy(out, k.Alerts)
	return out
}

// AlertAPI: both services use this interface to expose alerts to the user
type AlertAPI interface {
	GetAlerts() []string
}

// NormalService: honest view of KernelAuthority (no manipulation)
type NormalService struct {
	kernel *KernelAuthority
}

func (n NormalService) GetAlerts() []string {
	return n.kernel.GetAlerts()
}

// HookedService: compromised view that filters out certain alerts
// (simulates the rootkit hiding something from the user)
type HookedService struct {
	kernel *KernelAuthority
	hidden map[string]struct{}
}

func NewHookedService(k *KernelAuthority) *HookedService {
	return &HookedService{
		kernel: k,
		hidden: make(map[string]struct{}),
	}
}

func (h *HookedService) HideAlert(alert string) {
	h.hidden[alert] = struct{}{}
}

func (h HookedService) GetAlerts() []string {
	alerts := h.kernel.GetAlerts()
	out := []string{}
	for _, a := range alerts {
		if _, hide := h.hidden[a]; !hide {
			out = append(out, a)
		}
	}
	return out
}

// showAlerts: represents the user/application trusting whatever API is passed in
func showAlerts(api AlertAPI) {
	fmt.Println("[Application] Visible alerts:")
	for _, a := range api.GetAlerts() {
		fmt.Println("  -", a)
	}
}

// Auditor: compares real kernel state against the hooked view
// (cross-view detection to catch what the hook is hiding)
type Auditor struct {
	kernel *KernelAuthority
	api    AlertAPI
}

type AlertDiff struct {
	KernelView []string
	UserView   []string
	Hidden     []string
}

func NewAuditor(k *KernelAuthority, api AlertAPI) *Auditor {
	return &Auditor{kernel: k, api: api}
}

func (a Auditor) DiffAlerts() AlertDiff {
	k := a.kernel.GetAlerts()
	u := a.api.GetAlerts()

	km := make(map[string]struct{})
	for _, x := range k {
		km[x] = struct{}{}
	}
	for _, x := range u {
		delete(km, x)
	}

	hidden := []string{}
	for x := range km {
		hidden = append(hidden, x)
	}

	return AlertDiff{
		KernelView: k,
		UserView:   u,
		Hidden:     hidden,
	}
}

// Demo: kernel holds truth, hook hides one alert, auditor shows the difference
func main() {
	kernel := NewKernelAuthority()

	normal := NormalService{kernel: kernel}
	hooked := NewHookedService(kernel)

	// simulate hiding one of the alerts
	hooked.HideAlert("WARNING: suspicious process detected")

	fmt.Println("=== Victim UI (Hooked View) ===")
	showAlerts(hooked)

	fmt.Println("\n=== Auditor Cross-View Detection ===")
	auditor := NewAuditor(kernel, hooked)
	diff := auditor.DiffAlerts()

	fmt.Println("Kernel view:", diff.KernelView)
	fmt.Println("User view  :", diff.UserView)
	fmt.Println("Hidden     :", diff.Hidden)

	_ = normal // to avoid unused variable warning
}
