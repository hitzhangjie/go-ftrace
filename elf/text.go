package elf

import "github.com/pkg/errors"

// Text returns the bytes of .text section.
func (e *ELF) Text() (bytes []byte, err error) {
	if _, ok := e.cache["textBytes"]; !ok {
		if e.cache["textBytes"], err = e.SectionBytes(".text"); err != nil {
			return
		}
	}
	return e.cache["textBytes"].([]byte), nil
}

// FuncRawInstructions returns the raw instructions of the function with the given name,
// and the address of the function, and the offset of the function in the ELF file.
func (e *ELF) FuncRawInstructions(name string) (textBytes []byte, addr, offset uint64, err error) {
	lowpc, highpc, err := e.FuncPcRangeInDwarf(name)
	if err != nil {
		if lowpc, highpc, err = e.FuncPcRangeInSymtab(name); err != nil {
			return
		}
	}

	section := e.Section(".text")
	if textBytes, err = e.Text(); err != nil {
		return
	}

	if lowpc < section.Addr || highpc > uint64(len(textBytes))+section.Addr {
		err = errors.Wrap(PcRangeTooLargeErr, name)
		return
	}
	return textBytes[lowpc-section.Addr : highpc-section.Addr], lowpc, lowpc - section.Addr + section.Offset, nil
}
