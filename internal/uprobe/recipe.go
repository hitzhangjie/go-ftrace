package uprobe

import "debug/dwarf"

// RelRule is one probe-time memory copy relative to an interface data pointer.
// Steps are applied to that pointer the same way ArgRule stack ops are applied
// to a register: add offset, or dereference *(addr+offset).
type RelRule struct {
	Size  int
	Steps []ArgRule
}

const maxTypeRecipeRules = 4

// CompileTypeRecipe builds extra fetch rules for a concrete interface type.
// The rules are relative to the interface data word, so they are keyed only by
// the runtime type descriptor address — the same *errors.errorString has one
// recipe no matter which function or which interface slot it appears in.
func CompileTypeRecipe(t dwarf.Type) []RelRule {
	if t == nil {
		return nil
	}
	t = underlying(t)
	var rules []RelRule
	if typeIsDirect(t) {
		if pt, ok := t.(*dwarf.PtrType); ok {
			rules = relMemCaptures(pt.Type, nil)
		}
	} else {
		rules = relMemCaptures(t, nil)
	}
	if len(rules) > maxTypeRecipeRules {
		rules = rules[:maxTypeRecipeRules]
	}
	return rules
}

func relMemCaptures(t dwarf.Type, steps []ArgRule) []RelRule {
	t = underlying(t)
	st, ok := t.(*dwarf.StructType)
	if !ok {
		return nil
	}
	switch {
	case isString(st):
		return []RelRule{{Size: autoStringSize, Steps: appendStep(steps, 0, true)}}
	case isSlice(st), isInterface(st):
		return nil
	default:
		var out []RelRule
		for _, f := range st.Field {
			out = append(out, relMemCaptures(f.Type, appendStep(steps, f.ByteOffset, false))...)
		}
		return out
	}
}

func appendStep(steps []ArgRule, off int64, deref bool) []ArgRule {
	if off == 0 && !deref {
		out := make([]ArgRule, len(steps))
		copy(out, steps)
		return out
	}
	out := make([]ArgRule, len(steps)+1)
	copy(out, steps)
	out[len(steps)] = ArgRule{From: Stack, Offset: off, Dereference: deref}
	return out
}
