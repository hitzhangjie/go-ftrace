package uprobe

import (
	"debug/dwarf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/hitzhangjie/go-ftrace/elf"
)

// buildFixture compiles a single-file Go program into a non-optimized binary
// and returns its path. It skips the test if no Go toolchain is available.
func buildFixture(t *testing.T, src string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fixture\n\ngo 1.18\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "main")
	cmd := exec.Command("go", "build", "-gcflags", "all=-N -l", "-o", out, ".")
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", src, err, b)
	}
	return out
}

// fetchArgString renders a FetchArg in the canonical <varname=(EA):type>
// notation used by --fargs/--frets, e.g. "s.Name.data=(*+0(%ax)):c64".
func fetchArgString(f *FetchArg) string {
	inner := "%" + f.Rules[0].Register
	for _, r := range f.Rules[1:] {
		deref := ""
		if r.Dereference {
			deref = "*"
		}
		inner = fmt.Sprintf("%s+%d(%s)", deref, r.Offset, inner)
	}
	return fmt.Sprintf("%s=(%s):%s", f.Varname, inner, f.Type)
}

func TestAutoFetchEntryArgs(t *testing.T) {
	bin := buildFixture(t, "../../testdata/args/main.go")
	e, err := elf.New(bin)
	if err != nil {
		t.Fatalf("elf.New: %v", err)
	}

	cases := []struct {
		fn       string
		expected []string
	}{
		{
			fn:       "main.add",
			expected: []string{"a=(%ax):s64", "b=(%bx):s64"},
		},
		{
			fn:       "main.greet",
			expected: []string{"name.data=(%ax):u64", "name.len=(%bx):s64", "name.str=(+0(%ax)):c512"},
		},
		{
			fn: "main.sum",
			expected: []string{
				"nums.data=(%ax):u64",
				"nums.len=(%bx):s64",
				"nums.cap=(%cx):s64",
				"nums.arr=(+0(%ax)):c512",
			},
		},
		{
			fn:       "main.toggle",
			expected: []string{"on=(%ax):bool"},
		},
		{
			fn:       "main.(*Student).String",
			expected: []string{"s=(%ax):u64", "s.obj=(+0(%ax)):c512", "s.Name.str=(*+0(%ax)):c512"},
		},
	}

	for _, c := range cases {
		t.Run(c.fn, func(t *testing.T) {
			ea, _, _, _ := autoFetchArgs(e, c.fn)
			assertArgs(t, "arg", ea, c.expected)
		})
	}
}

func TestAutoFetchReturnValues(t *testing.T) {
	bin := buildFixture(t, "../../testdata/rets/main.go")
	e, err := elf.New(bin)
	if err != nil {
		t.Fatalf("elf.New: %v", err)
	}

	cases := []struct {
		fn       string
		expected []string
	}{
		{
			fn:       "main.add",
			expected: []string{"ret0=(%ax):s64"},
		},
		{
			fn:       "main.divmod",
			expected: []string{"ret0=(%ax):s64", "ret1=(%bx):s64"},
		},
		{
			fn:       "main.mayFail",
			expected: []string{"ret0.type=(+8(%ax)):u64", "ret0.data=(%bx):u64", "ret0.value=(+0(%bx)):c512"},
		},
		{
			fn: "main.send",
			expected: []string{
				"ret0=(%ax):u64",
				"ret0.obj=(+0(%ax)):c512",
				"ret0.Detail.type=(+8(*+0(+8(%ax)))):u64",
				"ret0.Detail.data=(+8(+8(%ax))):u64",
				"ret0.Detail.value=(*+8(+8(%ax))):c512",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.fn, func(t *testing.T) {
			_, _, ra, _ := autoFetchArgs(e, c.fn)
			assertArgs(t, "ret", ra, c.expected)
		})
	}
}

func TestAutoFetchNilCheck(t *testing.T) {
	bin := buildFixture(t, "../../testdata/rets/main.go")
	e, err := elf.New(bin)
	if err != nil {
		t.Fatalf("elf.New: %v", err)
	}

	// main.send returns *MeshError: every memory capture is a dereference of
	// AX and must be nil-checked. The pointer word itself is a register read.
	_, _, ra, _ := autoFetchArgs(e, "main.send")
	if len(ra) < 2 {
		t.Fatalf("got %d return args for main.send, want at least 2", len(ra))
	}
	if ra[0].NilCheck {
		t.Errorf("main.send pointer word %q: NilCheck = true, want false", ra[0].Varname)
	}
	for _, a := range ra[1:] {
		if !a.NilCheck {
			t.Errorf("main.send capture %q: NilCheck = false, want true", a.Varname)
		}
	}

	// main.mayFail returns error: following itab+8 must not run when itab is nil.
	_, _, ra, _ = autoFetchArgs(e, "main.mayFail")
	if len(ra) < 1 || !ra[0].NilCheck {
		t.Errorf("main.mayFail type word: NilCheck = false, want true so nil error is not read at address 8")
	}

	// main.add returns a plain int: no nil-checking.
	_, _, ra, _ = autoFetchArgs(e, "main.add")
	if len(ra) == 0 || ra[0].NilCheck {
		t.Errorf("main.add: unexpected nil-check metadata: %+v", ra)
	}
}

func TestAutoFetchInterfaceLimits(t *testing.T) {
	intType := &dwarf.IntType{BasicType: dwarf.BasicType{CommonType: dwarf.CommonType{Name: "int", ByteSize: 8}}}
	ifaceType := &dwarf.StructType{
		CommonType: dwarf.CommonType{Name: "runtime.iface", ByteSize: 16},
		StructName: "runtime.iface",
		Field:      []*dwarf.StructField{{Name: "tab"}, {Name: "data", ByteOffset: 8}},
	}

	// 5 ints + interface = 7 ABI words + 1 probe-time *data prefix = 8.
	fits := structWithIntsAndIface(intType, ifaceType, 5)
	args, values := deriveArgs(nil, []*elf.Variable{{Name: "v", Type: fits}})
	if len(args) != 8 {
		t.Fatalf("5 ints + interface = 8 leaves, got %d args", len(args))
	}
	if len(values) != 1 || values[0].leafCount() != len(args) {
		t.Fatalf("value leaves do not match args: values=%+v args=%d", values, len(args))
	}

	tooBig := structWithIntsAndIface(intType, ifaceType, 6)
	args, values = deriveArgs(nil, []*elf.Variable{{Name: "v", Type: tooBig}})
	if len(args) != 0 || len(values) != 0 {
		t.Fatalf("9-leaf struct should be skipped atomically, got args=%d values=%d", len(args), len(values))
	}
}

func structWithIntsAndIface(intType, ifaceType dwarf.Type, nints int) *dwarf.StructType {
	fields := make([]*dwarf.StructField, 0, nints+1)
	for i := 0; i < nints; i++ {
		fields = append(fields, &dwarf.StructField{Name: fmt.Sprintf("F%d", i), ByteOffset: int64(i * 8), Type: intType})
	}
	fields = append(fields, &dwarf.StructField{Name: "Err", ByteOffset: int64(nints * 8), Type: ifaceType})
	return &dwarf.StructType{
		CommonType: dwarf.CommonType{Name: "main.Result", ByteSize: int64((nints + 2) * 8)},
		StructName: "main.Result",
		Field:      fields,
	}
}

func TestAutoFetchEmptyInterfaceInMemory(t *testing.T) {
	efaceType := &dwarf.StructType{
		CommonType: dwarf.CommonType{Name: "runtime.eface", ByteSize: 16},
		StructName: "runtime.eface",
		Field:      []*dwarf.StructField{{Name: "_type"}, {Name: "data", ByteOffset: 8}},
	}
	outer := &dwarf.StructType{
		CommonType: dwarf.CommonType{Name: "main.Outer", ByteSize: 24},
		StructName: "main.Outer",
		Field:      []*dwarf.StructField{{Name: "Any", ByteOffset: 8, Type: efaceType}},
	}
	ptr := &dwarf.PtrType{CommonType: dwarf.CommonType{Name: "*main.Outer", ByteSize: 8}, Type: outer}

	args, values := deriveArgs(nil, []*elf.Variable{{Name: "v", Type: ptr}})
	if len(values) != 1 || values[0].WordCount != 1 || values[0].Captures < 1 {
		t.Fatalf("value plan = %+v, want pointer word plus captures", values)
	}
	if len(args) != values[0].leafCount() {
		t.Fatalf("got %d args, want %d", len(args), values[0].leafCount())
	}
	if len(args[0].Rules) != 1 || args[0].Rules[0].From != Register {
		t.Fatalf("pointer rule = %+v, want a single register fetch", args[0].Rules)
	}
}

func TestFillAutoFetchPrecedence(t *testing.T) {
	bin := buildFixture(t, "../../testdata/args/main.go")
	e, err := elf.New(bin)
	if err != nil {
		t.Fatalf("elf.New: %v", err)
	}

	fetchArgs := map[string][]*FetchArg{}
	retFetchArgs := map[string][]*FetchArg{}
	argValues := map[string][]*Value{}
	retValues := map[string][]*Value{}

	// Explicit entry rule for main.add must not be overwritten.
	explicit, err := newFetchArg("a", "(%bx):s64")
	if err != nil {
		t.Fatal(err)
	}
	fetchArgs["main.add"] = []*FetchArg{explicit}

	fillAutoFetch(e, []string{"main.add", "main.greet"}, fetchArgs, retFetchArgs, argValues, retValues, true, true)

	if len(fetchArgs["main.add"]) != 1 || fetchArgs["main.add"][0].Rules[0].Register != "bx" {
		t.Errorf("explicit entry rule for main.add was overwritten: %v", fetchArgs["main.add"])
	}
	if len(fetchArgs["main.greet"]) == 0 {
		t.Errorf("auto entry rules for main.greet were not derived")
	}
	if len(retFetchArgs["main.add"]) == 0 {
		t.Errorf("auto ret rules for main.add were not derived")
	}
}

func TestAutoFetchProtoUnmarshalBinary(t *testing.T) {
	bin := filepath.Join("..", "..", "examples", "trace_proto_unmarshal", "main")
	if _, err := os.Stat(bin); err != nil {
		t.Skip("example binary not built")
	}
	e, err := elf.New(bin)
	if err != nil {
		t.Fatalf("elf.New: %v", err)
	}

	ea, ev, _, _ := autoFetchArgs(e, "github.com/golang/protobuf/proto.Unmarshal")
	if len(ev) != 2 {
		t.Fatalf("Unmarshal values = %d, want 2 (slice + Message interface)", len(ev))
	}
	if ev[0].WordCount != 3 || ev[0].Captures != 1 {
		t.Fatalf("Unmarshal []byte plan = words=%d captures=%d, want 3+1", ev[0].WordCount, ev[0].Captures)
	}
	if ev[1].WordCount != 2 || ev[1].Captures != 1 {
		t.Fatalf("Unmarshal Message plan = words=%d captures=%d, want 2+1", ev[1].WordCount, ev[1].Captures)
	}
	assertArgs(t, "arg", ea, []string{
		"b.data=(%ax):u64",
		"b.len=(%bx):s64",
		"b.cap=(%cx):s64",
		"b.arr=(+0(%ax)):c512",
		"m.type=(+8(%di)):u64",
		"m.data=(%si):u64",
		"m.value=(+0(%si)):c512",
	})

	mea, mev, mra, mrv := autoFetchArgs(e, "github.com/golang/protobuf/proto.Marshal")
	if len(mev) != 1 || mev[0].WordCount != 2 || mev[0].Captures != 1 {
		t.Fatalf("Marshal argument plan = %+v, want one interface", mev)
	}
	assertArgs(t, "arg", mea, []string{
		"m.type=(+8(%ax)):u64",
		"m.data=(%bx):u64",
		"m.value=(+0(%bx)):c512",
	})
	if len(mrv) != 2 {
		t.Fatalf("Marshal returns = %d, want []byte + error", len(mrv))
	}
	if mrv[0].WordCount != 3 || mrv[0].Captures != 1 {
		t.Fatalf("Marshal []byte result plan = %+v", mrv[0])
	}
	if mrv[1].WordCount != 2 || mrv[1].Captures != 1 {
		t.Fatalf("Marshal error plan = %+v", mrv[1])
	}
	assertArgs(t, "ret", mra, []string{
		"ret0.data=(%ax):u64",
		"ret0.len=(%bx):s64",
		"ret0.cap=(%cx):s64",
		"ret0.arr=(+0(%ax)):c512",
		"ret1.type=(+8(%di)):u64",
		"ret1.data=(%si):u64",
		"ret1.value=(+0(%si)):c512",
	})
}

func TestAutoFetchNamedInterfaceAndByteSlice(t *testing.T) {
	uint8Type := &dwarf.UintType{BasicType: dwarf.BasicType{CommonType: dwarf.CommonType{Name: "uint8", ByteSize: 1}}}
	byteSlice := &dwarf.StructType{
		CommonType: dwarf.CommonType{Name: "[]uint8", ByteSize: 24},
		StructName: "[]uint8",
		Field: []*dwarf.StructField{
			{Name: "array", ByteOffset: 0, Type: ptrType("*uint8", uint8Type)},
			{Name: "len", ByteOffset: 8, Type: intType("int")},
			{Name: "cap", ByteOffset: 16, Type: intType("int")},
		},
	}
	namedIface := &dwarf.TypedefType{
		CommonType: dwarf.CommonType{Name: "proto.Message", ByteSize: 16},
		Type: &dwarf.TypedefType{
			CommonType: dwarf.CommonType{Name: "runtime.iface", ByteSize: 16},
			Type:       ifaceType(),
		},
	}

	args, values := deriveArgs(nil, []*elf.Variable{
		{Name: "b", Type: byteSlice},
		{Name: "m", Type: namedIface},
	})
	want := []string{
		"b.data=(%ax):u64",
		"b.len=(%bx):s64",
		"b.cap=(%cx):s64",
		"b.arr=(+0(%ax)):c512",
		"m.type=(+8(%di)):u64",
		"m.data=(%si):u64",
		"m.value=(+0(%si)):c512",
	}
	assertArgs(t, "arg", args, want)
	if len(values) != 2 {
		t.Fatalf("got %d values, want 2 (slice + named interface)", len(values))
	}
	if values[0].WordCount != 3 || values[0].Captures != 1 {
		t.Fatalf("slice plan = %+v, want 3 words + backing array", values[0])
	}
	if values[1].WordCount != 2 || values[1].Captures != 1 {
		t.Fatalf("interface plan = %+v, want 2 words + *data prefix", values[1])
	}
	if !args[3].NilCheck {
		t.Fatal("slice backing array must nil-check a possibly-empty data pointer")
	}
	if !args[4].NilCheck {
		t.Fatal("named non-empty interface type word must nil-check itab")
	}
	if !args[5].IfaceData || args[5].TypeIndex != 4 {
		t.Fatalf("interface data slot = %+v, want IfaceData with type index 4", args[5])
	}
}

func assertArgs(t *testing.T, kind string, got []*FetchArg, expected []string) {
	t.Helper()
	if len(got) != len(expected) {
		actual := make([]string, len(got))
		for i, a := range got {
			actual[i] = fetchArgString(a)
		}
		t.Fatalf("got %d %ss, want %d: %v", len(got), kind, len(expected), actual)
	}
	for i, want := range expected {
		if g := fetchArgString(got[i]); g != want {
			t.Errorf("%s[%d] = %s, want %s", kind, i, g, want)
		}
	}
}
