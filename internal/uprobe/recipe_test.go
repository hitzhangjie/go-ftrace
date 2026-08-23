package uprobe

import "testing"

func TestCompileTypeRecipeErrorString(t *testing.T) {
	ptr := ptrType("*errors.errorString", errorStringType())
	rules := CompileTypeRecipe(ptr)
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1 (string backing array)", len(rules))
	}
	if rules[0].Size != autoStringSize {
		t.Fatalf("size=%d, want %d", rules[0].Size, autoStringSize)
	}
	if len(rules[0].Steps) != 1 || !rules[0].Steps[0].Dereference || rules[0].Steps[0].Offset != 0 {
		t.Fatalf("steps=%+v, want a single deref at offset 0", rules[0].Steps)
	}
}

func TestCompileTypeRecipeIntHasNoExtras(t *testing.T) {
	if rules := CompileTypeRecipe(intType("int")); len(rules) != 0 {
		t.Fatalf("int recipe = %+v, want none", rules)
	}
}

func TestCompileTypeRecipeByteSlice(t *testing.T) {
	rules := CompileTypeRecipe(byteSliceType())
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1 (slice backing array)", len(rules))
	}
	if len(rules[0].Steps) != 1 || !rules[0].Steps[0].Dereference || rules[0].Steps[0].Offset != 0 {
		t.Fatalf("steps=%+v, want a single deref at offset 0", rules[0].Steps)
	}
}

func TestMarkIfaceSlots(t *testing.T) {
	args := []*FetchArg{
		{Varname: "ret0.type"},
		{Varname: "ret0.data"},
		{Varname: "ret0.value"},
		{Varname: "name.data"},
	}
	markIfaceSlots(args)
	if !args[1].IfaceData || args[1].TypeIndex != 0 {
		t.Fatalf("ret0.data slot = %+v", args[1])
	}
	if args[3].IfaceData {
		t.Fatal("string name.data must not be marked as interface data")
	}
}
