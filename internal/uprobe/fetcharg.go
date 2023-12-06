package uprobe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type FetchArg struct {
	Varname   string
	Statement string
	Type      string
	Size      int
	Rules     []*ArgRule
}

type ArgLocation int

const (
	Register ArgLocation = iota
	Stack
)

type ArgRule struct {
	From        ArgLocation
	Register    string
	Offset      int64
	Dereference bool
}

func parseFetchArgs(funcParams map[string]map[string]string) (fetchArgs map[string][]*FetchArg, err error) {
	fetchArgs = map[string][]*FetchArg{}
	for fname, params := range funcParams {
		for name, expr := range params {
			fa, err := newFetchArg(name, expr)
			if err != nil {
				return nil, err
			}
			fetchArgs[fname] = append(fetchArgs[fname], fa)
		}
	}
	return
}

func newFetchArg(varname, statement string) (_ *FetchArg, err error) {
	parts := strings.Split(statement, ":")
	if len(parts) != 2 {
		err = fmt.Errorf("type not found: %s", statement)
		return
	}

	argAddr := parts[0]
	argType := parts[1]

	// check the datatype
	switch argType[0] {
	case 'u', 's':
		switch argType[1:] {
		case "8", "16", "32", "64":
			break
		default:
			err = fmt.Errorf("only support 8/16/32/64 bits for u/s type: %s", argType)
			return
		}
	case 'c':
		switch argType[1:] {
		case "8", "16", "32", "64", "128", "256", "512":
			break
		default:
			err = fmt.Errorf("only support 8/16/32/64/128/256/512 bits for c type: %s", argType)
			return
		}
	default:
		err = fmt.Errorf("only support u/s/c type: %s", argType)
		return
	}

	targetSize, err := strconv.Atoi(argType[1:])
	if err != nil {
		return
	}
	targetSize /= 8

	// check the data address

	// like: s.name=(*+0(%ax)):c64, let's parse the rules for (*+0(%ax)),
	// then we'll get 2 rules: [stackRule *+0, registerRule %ax],
	// and reverse the rules, so final rules is: registerRule %ax, stackRule *+0].
	//
	// *+0, means the effective address is EA=*(%ax+0), so why not *(%ax)?
	// yeah, *(%eax) or ((%eax)) is much clearer, here we just want to simplify
	// the parsing logic in `newFilterOp(...)`
	rules := []*ArgRule{}
	buf := []byte{}
	for i := 0; i < len(argAddr); i++ {
		ch := argAddr[i]
		if ch != '(' && ch != ')' {
			buf = append(buf, ch)
			continue
		}
		if len(buf) > 0 {
			op, err := newFetchOp(string(buf))
			if err != nil {
				return nil, err
			}
			rules = append(rules, op)
			buf = []byte{}
			continue
		}
	}
	if len(buf) > 0 {
		op, err := newFetchOp(string(buf))
		if err != nil {
			return nil, err
		}
		rules = append(rules, op)
	}

	// reverse
	for i, j := 0, len(rules)-1; i < j; i, j = i+1, j-1 {
		rules[i], rules[j] = rules[j], rules[i]
	}

	return &FetchArg{
		Varname:   varname,
		Statement: statement,
		Size:      targetSize,
		Type:      argType,
		Rules:     rules,
	}, nil
}

func newFetchOp(op string) (_ *ArgRule, err error) {
	if len(op) == 0 {
		return nil, errors.New("invalid op: empty")
	}

	// then it may be a register
	if op[0] == '%' {
		switch op[1:] {
		case "ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15":
			break
		default:
			return nil, fmt.Errorf("unknown register: %s", op[1:])
		}
		return &ArgRule{
			From:     Register,
			Register: op[1:],
		}, nil
	}

	var dereference bool
	if op[0] == '*' {
		dereference = true
		op = op[1:]
	}

	// then it must be a stack offset
	offset, err := strconv.ParseInt(op, 10, 64)
	if err != nil {
		return
	}
	return &ArgRule{
		From:        Stack,
		Offset:      offset,
		Dereference: dereference,
	}, nil
}

func (f *FetchArg) SprintValue(data []uint8) (value string) {
	data = data[:f.Size]
	switch f.Type {
	case "u8":
		value = fmt.Sprintf("%d", data[0])
	case "u16":
		value = fmt.Sprintf("%d", binary.LittleEndian.Uint16(data))
	case "u32":
		value = fmt.Sprintf("%d", binary.LittleEndian.Uint32(data))
	case "u64":
		value = fmt.Sprintf("%d", binary.LittleEndian.Uint64(data))
	case "s8":
		value = fmt.Sprintf("%d", int8(data[0]))
	case "s16":
		value = fmt.Sprintf("%d", int16(binary.LittleEndian.Uint16(data)))
	case "s32":
		value = fmt.Sprintf("%d", int32(binary.LittleEndian.Uint32(data)))
	case "s64":
		value = fmt.Sprintf("%d", int64(binary.LittleEndian.Uint64(data)))
	case "f32":
		value = fmt.Sprintf("%f", float32(binary.LittleEndian.Uint32(data)))
	case "f64":
		value = fmt.Sprintf("%f", float64(binary.LittleEndian.Uint64(data)))
	case "c8", "c16", "c32", "c64", "c128", "c256", "c512":
		value = string(data[:f.Size])
	}
	return
}
