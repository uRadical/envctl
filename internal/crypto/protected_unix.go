//go:build !windows

package crypto

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// mlock prevents memory from being swapped
func (p *ProtectedBuffer) mlock() error {
	if len(p.data) == 0 {
		return nil
	}

	ptr := unsafe.Pointer(&p.data[0])
	err := unix.Mlock((*[1 << 30]byte)(ptr)[:len(p.data)])
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

	ptr := unsafe.Pointer(&p.data[0])
	err := unix.Munlock((*[1 << 30]byte)(ptr)[:len(p.data)])
	if err == nil {
		p.locked = false
	}
	return err
}
