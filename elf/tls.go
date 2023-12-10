package elf

import "debug/elf"

// FindGOffset returns the runtime.g offset
//
// see: github.com/go-delve/delve/proc/bininfo.go:setGStructOffsetElf,
//
// it summarizes how to get the runtime.g offset:
// This is a bit arcane. Essentially:
//   - If the program is pure Go, it can do whatever it wants, and puts the G
//     pointer at %fs-8 on 64 bit.
//   - %Gs is the index of private storage in GDT on 32 bit, and puts the G
//     pointer at -4(tls).
//   - Otherwise, Go asks the external linker to place the G pointer by
//     emitting runtime.tlsg, a TLS symbol, which is relocated to the chosen
//     offset in libc's TLS block.
//   - On ARM64 (but really, any architecture other than i386 and x86_64) the
//     offset is calculated using runtime.tls_g and the formula is different.
//
// well, this is a bit hard to master all this kind of history.
// but, we can show respect to the contributors.
func (e *ELF) FindGOffset() (offset int64, err error) {
	_, symnames, err := e.Symbols()
	if err != nil {
		return
	}
	// When external linking, runtime.tlsg stores offsets of TLS base address
	// to the thread base address.
	tlsg, ok := symnames["runtime.tlsg"]
	tls := e.Prog(elf.PT_TLS)
	if ok && tls != nil {
		// runtime.tlsg is a symbol, its symbol.Value is the offset to the
		// beginning of the that TLS block.
		//
		// FS register is the offsets which points to the end of the TLS block,
		// this block's size is memsz long.
		//
		// so, offsets where runtime.g stored = FS + runtime.tlsg.Value - memsz
		memsz := tls.Memsz + (-tls.Vaddr-tls.Memsz)&(tls.Align-1)
		return int64(^(memsz) + 1 + tlsg.Value), nil
	}
	// While inner linking, it's a fixed value -8 ... at least on x86+linux.
	return -8, nil
}
