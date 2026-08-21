package eventmanager

import (
	"bytes"
	"debug/dwarf"
	"encoding/binary"
	"io"
	"os"
	"testing"

	"github.com/hitzhangjie/go-ftrace/internal/bpf"
	"github.com/hitzhangjie/go-ftrace/internal/uprobe"
)

func TestRenderEventArgsKeepsLeavesAtomic(t *testing.T) {
	meshError := &uprobe.Value{
		Kind:       uprobe.KindStructPtr,
		Name:       "ret0",
		StructName: "main.MeshError",
		Fields: []*uprobe.Value{
			{Kind: uprobe.KindScalar, Name: "ret0.Code", Typ: "s64", Size: 8},
			{
				Kind: uprobe.KindInterface,
				Name: "ret0.Detail",
				RuntimeType: func(uint64) (dwarf.Type, error) {
					return &dwarf.PtrType{
						CommonType: dwarf.CommonType{Name: "*errors.errorString", ByteSize: 8},
						Type: &dwarf.StructType{
							CommonType: dwarf.CommonType{Name: "errors.errorString", ByteSize: 16},
							StructName: "errors.errorString",
						},
					}, nil
				},
			},
		},
	}
	fetchArgs := []*uprobe.FetchArg{
		{Varname: "ret0.Code"},
		{Varname: "ret0.Detail.type"},
		{Varname: "ret0.Detail.data"},
		{Varname: "ret0.Detail.value"},
	}
	up := uprobe.Uprobe{Funcname: "main.send", FetchArgs: fetchArgs, Values: []*uprobe.Value{meshError}}

	var event bpf.GoftraceEvent
	event.ArgCount = 4
	binary.LittleEndian.PutUint64(event.Args[0].Data[:], 500)
	binary.LittleEndian.PutUint64(event.Args[1].Data[:], 0x46f9c0)
	binary.LittleEndian.PutUint64(event.Args[2].Data[:], 0xc0001000)
	event.Args[3].ReadError = 1

	if got := renderEventArgs(up, event); got != "ret0=&main.MeshError{Code:500, Detail:<unavailable>}" {
		t.Fatalf("renderEventArgs() = %q", got)
	}
}

func TestRenderEventArgsRejectsCountMismatch(t *testing.T) {
	up := uprobe.Uprobe{
		Funcname: "main.send",
		FetchArgs: []*uprobe.FetchArg{
			{Varname: "ret0.Code"},
			{Varname: "ret0.Detail.type"},
		},
		Values: []*uprobe.Value{{Kind: uprobe.KindScalar, Name: "ret0", Typ: "s64", Size: 8}},
	}
	event := bpf.GoftraceEvent{ArgCount: 1}
	binary.LittleEndian.PutUint64(event.Args[0].Data[:], 1)

	if got := renderEventArgs(up, event); got != "<unavailable>" {
		t.Fatalf("renderEventArgs() = %q, want unavailable", got)
	}
}

func TestAggregateRejectsMismatchedReturn(t *testing.T) {
	m := &EventManager{
		aggregate:        true,
		adaptive:         true,
		pids:             map[uint32]*pidState{},
		suppressed:       map[traceKey]struct{}{},
		maxPendingEvents: 16,
	}
	s := m.pidState(1)
	entry := bpf.GoftraceEvent{Pid: 1, Goid: 2, Ip: 0x100, Location: eventLocationEntry}
	m.updateObservedStack(s, entry, uprobe.Uprobe{Address: 0x100})

	retProbe := uprobe.Uprobe{Address: 0x201, RelOffset: 1}
	event := bpf.GoftraceEvent{Pid: 1, Goid: 2, Ip: 0x201, Location: eventLocationRet, TraceFlags: traceFlagEnd}
	m.updateObservedStack(s, event, retProbe)

	if !m.CloseStack(event) {
		t.Fatal("TRACE_END must terminate the sample")
	}
	if !s.invalid[2] {
		t.Fatal("mismatched return must invalidate the sample")
	}
}

func TestNonAggregateAdaptiveBackpressure(t *testing.T) {
	// Non-aggregate mode still runs the adaptive backpressure: root samples are
	// rejected once in-flight events exceed the budget, the rejected sample is
	// suppressed until its root re-enters, and the whole sample is dropped.
	m := &EventManager{
		adaptive:         true,
		pids:             map[uint32]*pidState{},
		suppressed:       map[traceKey]struct{}{},
		maxPendingEvents: 2,
		pendingEvents:    2,
	}
	key := traceKey{pid: 1, goid: 2}

	root := bpf.GoftraceEvent{Pid: 1, Goid: 2, Ip: 0x100, Location: eventLocationEntry, TraceFlags: traceFlagStart}
	if m.Add(root) {
		t.Fatal("over-budget root sample must be rejected")
	}
	if m.droppedStacks != 1 || m.droppedOverBudget != 1 {
		t.Fatalf("dropped=%d over-budget=%d, want 1 and 1", m.droppedStacks, m.droppedOverBudget)
	}
	if _, ok := m.suppressed[key]; !ok {
		t.Fatal("over-budget sample must be suppressed")
	}

	nested := bpf.GoftraceEvent{Pid: 1, Goid: 2, Ip: 0x101, Location: eventLocationEntry}
	if m.Add(nested) {
		t.Fatal("suppressed-sample events must be dropped")
	}
	if m.droppedStacks != 1 {
		t.Fatalf("dropped=%d, want unchanged 1", m.droppedStacks)
	}

	// TRACE_START clears the suppression (Add then proceeds to uprobe
	// resolution, which fails in this fixture because there is no elf).
	m.pendingEvents = 0
	root.Ip = 0 // ResolveAddress rejects ip==0 without touching the nil elf
	if m.Add(root) {
		t.Fatal("root Add must fail at uprobe resolution in this fixture")
	}
	if _, ok := m.suppressed[key]; ok {
		t.Fatal("TRACE_START must clear suppression")
	}
}

func TestAggregateCloseStackWithoutAdaptiveUsesStackDepth(t *testing.T) {
	// With --adaptive-sample=false the BPF side never emits TRACE_END, so
	// aggregate mode must fall back to the stack-depth check: the aggregate is
	// produced when the root call's stack unwinds back to zero.
	m := &EventManager{
		aggregate:  true, // adaptive=false by default
		pids:       map[uint32]*pidState{},
		suppressed: map[traceKey]struct{}{},
	}
	s := m.pidState(1)

	entry := bpf.GoftraceEvent{Pid: 1, Goid: 2, Ip: 0x100, Location: eventLocationEntry}
	m.updateObservedStack(s, entry, uprobe.Uprobe{Address: 0x100})
	s.goEvents[2] = []Event{{GoftraceEvent: entry}}
	if m.CloseStack(entry) {
		t.Fatal("open stack must not close the sample")
	}

	ret := bpf.GoftraceEvent{Pid: 1, Goid: 2, Ip: 0x100, Location: eventLocationRet}
	m.updateObservedStack(s, ret, uprobe.Uprobe{Address: 0x100})
	if !m.CloseStack(ret) {
		t.Fatal("stack unwound to zero must close the sample")
	}
}

func TestTraceStartResetsIncompletePreviousSample(t *testing.T) {
	m := &EventManager{
		aggregate:        true,
		pids:             map[uint32]*pidState{},
		suppressed:       map[traceKey]struct{}{},
		maxPendingEvents: 16,
	}
	s := m.pidState(1)
	s.goEvents[2] = []Event{{GoftraceEvent: bpf.GoftraceEvent{Ip: 0x100}}}
	s.goEventStack[2] = []uint64{0x100}
	m.pendingEvents = 1

	event := bpf.GoftraceEvent{Pid: 1, Goid: 2, Ip: 0x200, Location: eventLocationEntry, TraceFlags: traceFlagStart}
	m.resetStaleSample(event)
	if got := len(s.goEvents[2]); got != 0 {
		t.Fatalf("events=%+v, want stale sample cleared", s.goEvents[2])
	}
	if m.droppedStacks != 1 {
		t.Fatalf("discarded=%d, want 1 stale sample", m.droppedStacks)
	}
}

func TestRecordAggAccumulatesObservedAndEstimatedCounts(t *testing.T) {
	s := newPidState()
	s.recordAgg("main.hot", 5, "ok", 8)
	s.recordAgg("main.hot", 5, "ok", 64)

	agg := s.agg["main.hot"]
	if agg.calls != 2 || agg.weightedCalls != 72 {
		t.Fatalf("calls=%d weighted=%d, want 2 and 72", agg.calls, agg.weightedCalls)
	}
	if agg.latencies[0] != 2 || agg.weightedLatencies[0] != 72 {
		t.Fatalf("latency observed=%d weighted=%d, want 2 and 72", agg.latencies[0], agg.weightedLatencies[0])
	}
	if got := agg.retvals["ok"]; got.count != 2 || got.weightedCount != 72 {
		t.Fatalf("retval=%+v, want observed 2 and weighted 72", got)
	}
}

func TestRecordRetvalUsesBoundedHeavyHitters(t *testing.T) {
	agg := newFuncAgg()
	for i := 0; i < maxAggregateRetvals*4; i++ {
		agg.recordRetval(string(rune(i+1)), 1)
	}
	for i := 0; i < 1000; i++ {
		agg.recordRetval("hot", 1)
	}

	if len(agg.retvals) != maxAggregateRetvals {
		t.Fatalf("retvals size=%d, want %d", len(agg.retvals), maxAggregateRetvals)
	}
	if count, ok := agg.retvals["hot"]; !ok || count.count < 1000 {
		t.Fatalf("hot value missing or under-counted: %+v, present=%v", count, ok)
	}
}

func TestRecordRetvalReplacementKeepsObservedLowerBound(t *testing.T) {
	agg := newFuncAgg()
	for i := 0; i < maxAggregateRetvals; i++ {
		agg.recordRetval(string(rune(i+1)), 8)
	}
	agg.recordRetval("replacement", 64)

	got := agg.retvals["replacement"]
	if got.count != 1 || got.weightedCount != 72 || got.weightedError != 8 {
		t.Fatalf("replacement=%+v, want observed lower bound 1, weighted 72±8", got)
	}
}

func TestRecordRetvalIsExactBeforeCapacity(t *testing.T) {
	agg := newFuncAgg()
	agg.recordRetval("ok", 8)
	agg.recordRetval("ok", 8)

	if got := agg.retvals["ok"]; got.count != 2 || got.weightedCount != 16 {
		t.Fatalf("count=%+v, want observed 2 and weighted 16", got)
	}
}

func TestRenderEventArgsDoesNotReusePreviousLeafData(t *testing.T) {
	up := uprobe.Uprobe{
		Funcname:  "main.send",
		FetchArgs: []*uprobe.FetchArg{{Varname: "ret0.Code"}},
		Values: []*uprobe.Value{{
			Kind: uprobe.KindScalar,
			Name: "ret0.Code",
			Typ:  "s64",
			Size: 8,
		}},
	}

	first := bpf.GoftraceEvent{ArgCount: 1}
	binary.LittleEndian.PutUint64(first.Args[0].Data[:], 500)
	if got := renderEventArgs(up, first); got != "ret0.Code=500" {
		t.Fatalf("first render = %q", got)
	}

	second := bpf.GoftraceEvent{ArgCount: 1}
	second.Args[0].ReadError = 1
	if got := renderEventArgs(up, second); got != "ret0.Code=<unavailable>" {
		t.Fatalf("failed read reused data: %q", got)
	}
}

func TestPrintWindowStatsReportsDeltas(t *testing.T) {
	prev := bpf.RuntimeStats{WantedRoots: 100, SampledOutRoots: 0, EmittedEvents: 1000, DroppedEvents: 500}
	curr := bpf.RuntimeStats{WantedRoots: 400, SampledOutRoots: 200, EmittedEvents: 2000, DroppedEvents: 600}

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	PrintWindowStats(prev, curr)
	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	want := "window: detected=300, skipped=200 (66.67%), queued=1000, dropped=100 (9.09%, queue full)\n"
	if got := buf.String(); got != want {
		t.Fatalf("PrintWindowStats() = %q, want %q", got, want)
	}
}

func TestPrintWindowStatsFirstWindowIsZero(t *testing.T) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	PrintWindowStats(bpf.RuntimeStats{}, bpf.RuntimeStats{WantedRoots: 50, EmittedEvents: 300})
	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	want := "window: detected=50, skipped=0 (0.00%), queued=300, dropped=0 (0.00%, queue full)\n"
	if got := buf.String(); got != want {
		t.Fatalf("PrintWindowStats() = %q, want %q", got, want)
	}
}
