package uprobe

type UprobeLocation int

const (
	AtEntry UprobeLocation = iota
	AtRet
	AtGoroutineExit
)

type Uprobe struct {
	Funcname string
	// absolute address of the function entry
	Address uint64
	// absolute offset to the binary entry (ELF file beginning)
	AbsOffset uint64
	// relative to the function entry
	RelOffset uint64
	// location of the probe
	Location UprobeLocation
	// fetch arguments
	FetchArgs []*FetchArg

	Wanted bool
}
