package uprobe

type UprobeLocation int

const (
	AtEntry UprobeLocation = iota
	AtRet
	AtGoroutineExit
)

type Uprobe struct {
	Funcname  string
	Address   uint64         // absolute virtual address of the probe point (function entry or RET instruction)
	AbsOffset uint64         // absolute offset to the binary entry (ELF file beginning)
	RelOffset uint64         // relative to the function entry
	Location  UprobeLocation // location of the probe
	FetchArgs []*FetchArg    // fetch arguments
	Values    []*Value       // dwarf.Type descriptors for auto-fetch rendering; empty in manual --fargs/--frets mode
	Wanted    bool
}
