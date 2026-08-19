package uprobe

import (
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
	reg := f.Rules[0].Register
	var ea string
	if len(f.Rules) == 1 {
		ea = fmt.Sprintf("(%%%s)", reg)
	} else {
		r := f.Rules[1]
		deref := ""
		if r.Dereference {
			deref = "*"
		}
		ea = fmt.Sprintf("(%s+%d(%%%s))", deref, r.Offset, reg)
	}
	return fmt.Sprintf("%s=%s:%s", f.Varname, ea, f.Type)
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
			expected: []string{"name.data=(+0(%ax)):c64", "name.len=(%bx):s64"},
		},
		{
			fn:       "main.sum",
			expected: []string{"nums.data=(%ax):u64", "nums.len=(%bx):s64", "nums.cap=(%cx):s64"},
		},
		{
			fn:       "main.toggle",
			expected: []string{"on=(%ax):u8"},
		},
		{
			fn:       "main.(*Student).String",
			expected: []string{"s.Name.data=(*+0(%ax)):c64", "s.Name.len=(+8(%ax)):s64", "s.Age=(+16(%ax)):s64"},
		},
	}

	for _, c := range cases {
		t.Run(c.fn, func(t *testing.T) {
			ea, _ := autoFetchArgs(e, c.fn)
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
			expected: []string{"ret0.itab=(%ax):u64", "ret0.data=(%bx):u64"},
		},
		{
			fn:       "main.send",
			expected: []string{"ret0.Code=(+0(%ax)):s64", "ret0.Detail.itab=(+8(%ax)):u64", "ret0.Detail.data=(+16(%ax)):u64"},
		},
	}

	for _, c := range cases {
		t.Run(c.fn, func(t *testing.T) {
			_, ra := autoFetchArgs(e, c.fn)
			assertArgs(t, "ret", ra, c.expected)
		})
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

	// Explicit entry rule for main.add must not be overwritten.
	explicit, err := newFetchArg("a", "(%bx):s64")
	if err != nil {
		t.Fatal(err)
	}
	fetchArgs["main.add"] = []*FetchArg{explicit}

	fillAutoFetch(e, []string{"main.add", "main.greet"}, fetchArgs, retFetchArgs)

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
