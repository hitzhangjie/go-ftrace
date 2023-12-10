package elf

import "debug/elf"

// Section returns the ELF section with the given name.
func (f *ELF) Section(s string) *elf.Section {
	return f.elfFile.Section(s)
}

// SectionBytes returns the bytes of the ELF section with the given name.
func (f *ELF) SectionBytes(s string) (bytes []byte, err error) {
	section := f.elfFile.Section(s)
	bytes = make([]byte, section.Size)
	_, err = f.binFile.ReadAt(bytes, int64(section.Offset))
	return
}

// AddressToOffset converts an address to an offset in the ELF file.
func (f *ELF) AddressToOffset(addr uint64) (offset uint64, err error) {
	textSection := f.Section(".text")
	return addr - textSection.Addr, nil
}

// Prog returns the ELF program with the given type.
func (e *ELF) Prog(typ elf.ProgType) *elf.Prog {
	for _, prog := range e.elfFile.Progs {
		if prog.Type == typ {
			return prog
		}
	}
	return nil
}
