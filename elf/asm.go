package elf

import (
	"golang.org/x/arch/x86/x86asm"
)

// FuncInstructions returns the instructions of function `name` in ELF file
func (e *ELF) FuncInstructions(name string) (insts []x86asm.Inst, addr, offset uint64, err error) {
	raw, addr, offset, err := e.FuncRawInstructions(name)
	if err != nil {
		return
	}
	return e.ResolveInstructions(raw), addr, offset, nil
}

// FuncRetOffsets returns the offsets of RET instructions of function `name` in ELF file
//
// Note: there may be multiple RET instructions in a function, so we return a slice of offsets
func (e *ELF) FuncRetOffsets(name string) (offsets []uint64, err error) {
	insts, _, offset, err := e.FuncInstructions(name)
	if err != nil {
		return
	}

	for _, inst := range insts {
		if inst.Op == x86asm.RET {
			offsets = append(offsets, offset)
		}
		offset += uint64(inst.Len)
	}
	return
}

// ResolveInstructions resolves the bytes to x86 instructions
func (e *ELF) ResolveInstructions(bytes []byte) (insts []x86asm.Inst) {
	if len(bytes) == 0 {
		return
	}
	for {
		inst, err := x86asm.Decode(bytes, 64)
		if err != nil {
			inst = x86asm.Inst{Len: 1}
		}
		insts = append(insts, inst)
		bytes = bytes[inst.Len:]
		if len(bytes) == 0 {
			break
		}
	}
	return
}
