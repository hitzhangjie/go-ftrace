package uprobe

import (
	"debug/dwarf"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hitzhangjie/go-ftrace/elf"
)

var (
	autoOnce sync.Once
	autoBin  string
	autoErr  error
)

// buildAutoFixture compiles testdata/auto, the catalog used by automatic
// DWARF fetch tests (args, rets, error, Stringer, proto.Message).
func buildAutoFixture(t *testing.T) string {
	t.Helper()
	autoOnce.Do(func() {
		if _, err := exec.LookPath("go"); err != nil {
			autoErr = err
			return
		}
		dir, err := os.MkdirTemp("", "goftrace-auto-")
		if err != nil {
			autoErr = err
			return
		}
		autoBin, autoErr = compileModule(dir, filepath.Join("..", "..", "testdata", "auto"))
	})
	if autoErr != nil {
		if _, ok := autoErr.(*exec.Error); ok {
			t.Skip("go toolchain not available")
		}
		t.Fatalf("build testdata/auto: %v", autoErr)
	}
	return autoBin
}

func compileModule(dir, srcDir string) (string, error) {
	if err := copyTree(srcDir, dir); err != nil {
		return "", fmt.Errorf("copy %s: %w", srcDir, err)
	}
	out := filepath.Join(dir, "main")
	cmd := exec.Command("go", "build", "-gcflags", "all=-N -l", "-o", out, ".")
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build %s: %v\n%s", srcDir, err, b)
	}
	return out, nil
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		name := info.Name()
		if !info.IsDir() && (name == "main" || strings.HasSuffix(name, ".s")) {
			return nil
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
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
	bin := buildAutoFixture(t)
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
	bin := buildAutoFixture(t)
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
		{
			fn:       "main.makeGreeting",
			expected: []string{"ret0.data=(%ax):u64", "ret0.len=(%bx):s64", "ret0.str=(+0(%ax)):c512"},
		},
		{
			fn:       "main.newStudentPtr",
			expected: []string{"ret0=(%ax):u64", "ret0.obj=(+0(%ax)):c512", "ret0.Name.str=(*+0(%ax)):c512"},
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
	bin := buildAutoFixture(t)
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
	bin := buildAutoFixture(t)
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

func TestAutoFetchInterfaces(t *testing.T) {
	bin := buildAutoFixture(t)
	e, err := elf.New(bin)
	if err != nil {
		t.Fatalf("elf.New: %v", err)
	}

	cases := []struct {
		fn     string
		args   []string
		rets   []string
		nEntry int
		nRet   int
	}{
		{
			fn: "main.stringify",
			args: []string{
				"s.type=(+8(%ax)):u64",
				"s.data=(%bx):u64",
				"s.value=(+0(%bx)):c512",
			},
			rets: []string{
				"ret0.data=(%ax):u64",
				"ret0.len=(%bx):s64",
				"ret0.str=(+0(%ax)):c512",
			},
			nEntry: 1,
			nRet:   1,
		},
		{
			fn: "main.handleError",
			args: []string{
				"err.type=(+8(%ax)):u64",
				"err.data=(%bx):u64",
				"err.value=(+0(%bx)):c512",
			},
			rets:   []string{"ret0=(%ax):bool"},
			nEntry: 1,
			nRet:   1,
		},
		{
			fn: "main.wrapError",
			args: []string{
				"err.type=(+8(%ax)):u64",
				"err.data=(%bx):u64",
				"err.value=(+0(%bx)):c512",
			},
			rets: []string{
				"ret0.type=(+8(%ax)):u64",
				"ret0.data=(%bx):u64",
				"ret0.value=(+0(%bx)):c512",
			},
			nEntry: 1,
			nRet:   1,
		},
		{
			fn: "main.printAny",
			args: []string{
				"v.type=(%ax):u64",
				"v.data=(%bx):u64",
				"v.value=(+0(%bx)):c512",
			},
			nEntry: 1,
		},
	}

	for _, c := range cases {
		t.Run(c.fn, func(t *testing.T) {
			ea, ev, ra, rv := autoFetchArgs(e, c.fn)
			if c.nEntry != 0 && len(ev) != c.nEntry {
				t.Errorf("entry values = %d, want %d", len(ev), c.nEntry)
			}
			if c.nRet != 0 && len(rv) != c.nRet {
				t.Errorf("ret values = %d, want %d", len(rv), c.nRet)
			}
			if c.args != nil {
				assertArgs(t, "arg", ea, c.args)
			}
			if c.rets != nil {
				assertArgs(t, "ret", ra, c.rets)
			}
		})
	}
}

func TestAutoFetchProtoMessage(t *testing.T) {
	bin := buildAutoFixture(t)
	e, err := elf.New(bin)
	if err != nil {
		t.Fatalf("elf.New: %v", err)
	}

	unmarshal := []string{
		"b.data=(%ax):u64",
		"b.len=(%bx):s64",
		"b.cap=(%cx):s64",
		"b.arr=(+0(%ax)):c512",
		"m.type=(+8(%di)):u64",
		"m.data=(%si):u64",
		"m.value=(+0(%si)):c512",
	}
	marshalArgs := []string{
		"m.type=(+8(%ax)):u64",
		"m.data=(%bx):u64",
		"m.value=(+0(%bx)):c512",
	}
	marshalRets := []string{
		"ret0.data=(%ax):u64",
		"ret0.len=(%bx):s64",
		"ret0.cap=(%cx):s64",
		"ret0.arr=(+0(%ax)):c512",
		"ret1.type=(+8(%di)):u64",
		"ret1.data=(%si):u64",
		"ret1.value=(+0(%si)):c512",
	}

	for _, fn := range []string{
		"main.unmarshalMsg",
		"google.golang.org/protobuf/proto.Unmarshal",
	} {
		t.Run(fn, func(t *testing.T) {
			ea, ev, _, _ := autoFetchArgs(e, fn)
			if len(ev) != 2 {
				t.Fatalf("values = %d, want 2 (slice + Message)", len(ev))
			}
			if ev[0].WordCount != 3 || ev[0].Captures != 1 {
				t.Fatalf("[]byte plan = words=%d captures=%d, want 3+1", ev[0].WordCount, ev[0].Captures)
			}
			if ev[1].WordCount != 2 || ev[1].Captures != 1 {
				t.Fatalf("Message plan = words=%d captures=%d, want 2+1", ev[1].WordCount, ev[1].Captures)
			}
			assertArgs(t, "arg", ea, unmarshal)
		})
	}

	for _, fn := range []string{
		"main.marshalMsg",
		"google.golang.org/protobuf/proto.Marshal",
	} {
		t.Run(fn, func(t *testing.T) {
			ea, ev, ra, rv := autoFetchArgs(e, fn)
			if len(ev) != 1 || ev[0].WordCount != 2 || ev[0].Captures != 1 {
				t.Fatalf("argument plan = %+v, want one interface", ev)
			}
			assertArgs(t, "arg", ea, marshalArgs)
			if len(rv) != 2 {
				t.Fatalf("returns = %d, want []byte + error", len(rv))
			}
			if rv[0].WordCount != 3 || rv[0].Captures != 1 {
				t.Fatalf("[]byte result plan = %+v", rv[0])
			}
			if rv[1].WordCount != 2 || rv[1].Captures != 1 {
				t.Fatalf("error plan = %+v", rv[1])
			}
			assertArgs(t, "ret", ra, marshalRets)
		})
	}
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
