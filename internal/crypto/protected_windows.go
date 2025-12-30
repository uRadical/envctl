//go:build windows

package crypto

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// mlock prevents memory from being swapped
func (p *ProtectedBuffer) mlock() error {
	if len(p.data) == 0 {
		return nil
	}

	err := windows.VirtualLock(uintptr(unsafe.Pointer(&p.data[0])), uintptr(len(p.data)))
	if err == nil {
		p.locked = true
	}
	return err
}

// munlock allows memory to be swapped again
func (p *ProtectedBuffer) munlock() error {
	if len(p.data) == 0 {
		return nil
	}

	err := windows.VirtualUnlock(uintptr(unsafe.Pointer(&p.data[0])), uintptr(len(p.data)))
	if err == nil {
		p.locked = false
	}
	return err
}
