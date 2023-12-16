package uprobe

type UprobeLocation int

const (
	AtEntry UprobeLocation = iota
	AtRet
	AtGoroutineExit
)

type Uprobe struct {
	Funcname  string
	Address   uint64         // absolute address of the function entry
	AbsOffset uint64         // absolute offset to the binary entry (ELF file beginning)
	RelOffset uint64         // relative to the function entry
	Location  UprobeLocation // location of the probe
	FetchArgs []*FetchArg    // fetch arguments
	Wanted    bool
}
