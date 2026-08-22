// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"

#define MAX_DATA_SIZE 64

#define ENTPOINT 0
#define RETPOINT 1
#define GOROUTINE_EXIT 2

#define TRACE_START 1
#define TRACE_END 2
#define TRACE_ABORT 4
#define MAX_SAMPLE_EVENTS 4096

// offset of `task_struct->thread_struct->fsbase`, `fsbase` contains the TLS
// offset. On Linux register `FS` is used to load the TLS base address.
#define fsbase_off (offsetof(struct task_struct, thread) + offsetof(struct thread_struct, fsbase))

char __license[] SEC("license") = "Dual MIT/GPL";

// bpf config, we need to get goid by reading kernel datastructure with the help of config
//
// see: `fsbase_off` helps to read the TLS base address of the current task,
// then we can get the runtime.g address by reading TLS+g_offset,
// then we can get the runtime.go->goid by reading TLS+g_offset+goid_offset.
struct config
{
	__s64 goid_offset;
	__s64 g_offset;
	// ftrace's pid namespace (from fstat(/proc/self/ns/pid)). Used with
	// bpf_get_ns_current_pid_tgid so event.pid is the TGID that userspace
	// process_vm_readv can look up. bpf_get_current_pid_tgid() returns the
	// init-namespace IDs, which are wrong inside WSL2/systemd or containers.
	__u64 pidns_dev;
	__u64 pidns_ino;
	bool fetch_args;
	bool adaptive_sampling;
	__u8 padding[6];
};

// add volatile to avoid compiler optimization (cache data in register),
// and x86 CPU is strong-consistent ... so on x86 volatile is enough
// to guarantee the visibility of the data btw tasks.
//
// CONFIG is overwritten by `spec.RewriteConstants(map[string]interface{}{"CONFIG": cfg})`
static volatile const struct config CONFIG = {};

// One fetched leaf. read_error is set when any userspace memory read needed
// by the rule fails; userspace must render that leaf as unavailable rather
// than interpreting the zeroed payload as a real value.
struct arg_data
{
	__u8 data[MAX_DATA_SIZE];
	__u8 is_nil;
	__u8 read_error;
	__u8 padding[6];
};

// One queue element contains the event and all of its fetched leaves. Keeping
// them in a single record is essential: two independent FIFO queues can be
// overwritten independently under load and permanently associate one event
// with another event's arguments.
struct event
{
	__u64 goid;
	__u64 ip;
	__u64 bp;
	__u64 caller_ip;
	__u64 caller_bp;
	__u64 time_ns;
	__u32 pid;
	__u32 sample_denominator;
	__u8 location;
	__u8 arg_count;
	__u8 trace_flags;
	__u8 padding;
	struct arg_data args[8];
};

// force emitting these structs into the ELF.
const struct event *_ __attribute__((unused));
const struct arg_data *___ __attribute__((unused));

// arg_rule.type values; they must stay in sync with the Go ArgLocation enum
// (Register = 0, Stack = 1) in internal/uprobe/fetcharg.go.
enum arg_rule_type
{
	ARG_RULE_REG = 0,
	ARG_RULE_MEMORY = 1,
};

// fetch 1 arg needs several rules (at most 8 rules), each rule is a struct arg_rule
struct arg_rule
{
	__u8 type;
	__u8 reg;
	__u8 size;
	__u8 length;
	__s16 offsets[8];
	__u8 dereference[8];
	// when set, the base register holds a pointer that may be nil; if the
	// pointer is 0 the fetched value is reported as nil instead of being
	// dereferenced (used for struct-pointer arguments/return values).
	__u8 nil_check;
};

// fetch 1 arg needs several rules (at most 8 rules)
struct arg_rules
{
	__u8 length;
	struct arg_rule rules[8];
};

const struct arg_rules *__ __attribute__((unused));

// key of `should_trace_goid` map. It is scoped by pid so that goroutine IDs
// belonging to different process instances of the same binary do not collide:
// two processes may both have a goroutine whose goid is, say, 42.
//
// The explicit `_pad` member keeps the key a deterministic 16 bytes (goid is
// 8-byte aligned); without it the compiler would insert implicit padding whose
// bytes are left unspecified by aggregate initialization, which would break
// hash lookups.
struct goid_key
{
	__u32 pid;
	__u32 _pad;
	__u64 goid;
};

// denominator=1 means full collection; N>1 admits approximately one out of
// every N wanted root calls. Userspace updates this array map at runtime.
struct sample_config
{
	__u32 denominator;
	__u32 _pad;
};

struct runtime_stats
{
	__u64 wanted_roots;
	__u64 admitted_roots;
	__u64 sampled_out_roots;
	__u64 emitted_events;
	__u64 dropped_events;
	__u64 aborted_roots;
	__u64 state_insert_failures;
};

// In adaptive mode a sampled goroutine is retained until the wanted root call
// returns. root_depth keeps recursive calls of that same wanted function from
// ending the sample prematurely.
struct trace_state
{
	__u64 root_ip;
	__u64 last_ip;
	__u64 last_bp;
	__u32 root_depth;
	__u32 event_count;
	__u32 sample_denominator;
	__u32 _pad;
};

const struct sample_config *____ __attribute__((unused));
const struct trace_state *_____ __attribute__((unused));
const struct runtime_stats *______ __attribute__((unused));

struct bpf_map_def SEC("maps") arg_rules_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct arg_rules),
	.max_entries = 100,
};

struct bpf_map_def SEC("maps") event_queue = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(struct event),
	.max_entries = 10000,
};

struct bpf_map_def SEC("maps") event_buffer = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct event),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") sample_config_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct sample_config),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") runtime_stats_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct runtime_stats),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") should_trace_goid = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct goid_key),
	.value_size = sizeof(struct trace_state),
	.max_entries = 10000,
};

struct bpf_map_def SEC("maps") should_trace_rip = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(bool),
	.max_entries = 10000,
};

// Maps every RET probe of a wanted function to that function's entry IP.
struct bpf_map_def SEC("maps") should_trace_ret = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u64),
	.max_entries = 10000,
};

static __always_inline
	__u64
	get_goid()
{
	__u64 tls_base, g_addr, goid;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	bpf_probe_read_kernel(&tls_base, sizeof(tls_base), (void *)task + fsbase_off);
	bpf_probe_read_user(&g_addr, sizeof(g_addr), (void *)(tls_base + CONFIG.g_offset));
	bpf_probe_read_user(&goid, sizeof(goid), (void *)(g_addr + CONFIG.goid_offset));
	return goid;
}

// get_pid returns the tgid of the current task as seen from ftrace's pid
// namespace. Userspace uses this value with process_vm_readv / /proc/<pid>,
// which resolve PIDs in the caller's namespace — not the kernel init ns.
static __always_inline
	__u32
	get_pid()
{
	struct bpf_pidns_info ns = {};

	if (CONFIG.pidns_dev && CONFIG.pidns_ino)
	{
		if (!bpf_get_ns_current_pid_tgid(CONFIG.pidns_dev, CONFIG.pidns_ino, &ns, sizeof(ns)) && ns.tgid)
			return ns.tgid;
	}
	return bpf_get_current_pid_tgid() >> 32;
}

// read register `reg` data from `ctx` into `regval`
static __always_inline void read_reg(struct pt_regs *ctx, __u8 reg, __u64 *regval)
{
	switch (reg)
	{
	case 0:
		bpf_probe_read_kernel(regval, sizeof(ctx->ax), &ctx->ax);
		break;
	case 1:
		bpf_probe_read_kernel(regval, sizeof(ctx->dx), &ctx->dx);
		break;
	case 2:
		bpf_probe_read_kernel(regval, sizeof(ctx->cx), &ctx->cx);
		break;
	case 3:
		bpf_probe_read_kernel(regval, sizeof(ctx->bx), &ctx->bx);
		break;
	case 4:
		bpf_probe_read_kernel(regval, sizeof(ctx->si), &ctx->si);
		break;
	case 5:
		bpf_probe_read_kernel(regval, sizeof(ctx->di), &ctx->di);
		break;
	case 6:
		bpf_probe_read_kernel(regval, sizeof(ctx->bp), &ctx->bp);
		break;
	case 7:
		bpf_probe_read_kernel(regval, sizeof(ctx->sp), &ctx->sp);
		break;
	case 8:
		bpf_probe_read_kernel(regval, sizeof(ctx->r8), &ctx->r8);
		break;
	case 9:
		bpf_probe_read_kernel(regval, sizeof(ctx->r9), &ctx->r9);
		break;
	case 10:
		bpf_probe_read_kernel(regval, sizeof(ctx->r10), &ctx->r10);
		break;
	case 11:
		bpf_probe_read_kernel(regval, sizeof(ctx->r11), &ctx->r11);
		break;
	case 12:
		bpf_probe_read_kernel(regval, sizeof(ctx->r12), &ctx->r12);
		break;
	case 13:
		bpf_probe_read_kernel(regval, sizeof(ctx->r13), &ctx->r13);
		break;
	case 14:
		bpf_probe_read_kernel(regval, sizeof(ctx->r14), &ctx->r14);
		break;
	case 15:
		bpf_probe_read_kernel(regval, sizeof(ctx->r15), &ctx->r15);
		break;
	}
	return;
}

static __always_inline void fetch_args_from_reg(struct pt_regs *ctx, struct arg_data *data, struct arg_rule *rule)
{
	read_reg(ctx, rule->reg, (__u64 *)&data->data);
}

static __always_inline void fetch_args_from_memory(struct pt_regs *ctx, struct arg_data *data, struct arg_rule *rule)
{
	// first read the address from register (well, it maybe a immediate value)
	__u64 addr = 0;
	read_reg(ctx, rule->reg, &addr);

	// when the base register holds a possibly-nil pointer and it is actually
	// nil, do not dereference (which would read from address 0); instead mark
	// the value as nil and leave the payload zeroed.
	if (rule->nil_check && addr == 0)
	{
		data->is_nil = 1;
		return;
	}

	// then do other addressing rules
	for (int i = 0; i < 8 && i < rule->length; i++)
	{
		// if expr = *+8(+2(%eax)), for *+8 part, we need to dereference the address
		if (rule->dereference[i] == 1)
		{
			if (bpf_probe_read_user(&addr, sizeof(addr), (void *)addr + rule->offsets[i]) != 0)
			{
				data->read_error = 1;
				return;
			}
		}
		// if the rule is +2 part, then we just add the offset to the address
		else
		{
			addr += rule->offsets[i];
		}
	}

	// finally, we got the EA (effective address), then read the data from it,
	// make sure the data size is not larger than MAX_DATA_SIZE
	if (bpf_probe_read_user(&data->data,
						rule->size < MAX_DATA_SIZE ? rule->size : MAX_DATA_SIZE,
						(void *)addr) != 0)
		data->read_error = 1;
}

// Fetch all leaves directly into the event scratch value. The whole event is
// subsequently pushed once, so queue overwrite can only drop a complete event.
static __always_inline void fetch_args(struct pt_regs *ctx, struct event *e)
{
	struct arg_rules *rules = bpf_map_lookup_elem(&arg_rules_map, &e->ip);
	if (!rules)
		return;

	e->arg_count = rules->length;
	for (int i = 0; i < 8 && i < rules->length; i++)
	{
		struct arg_data *data = &e->args[i];
		__builtin_memset(data, 0, sizeof(*data));
		switch (rules->rules[i].type)
		{
		case ARG_RULE_REG:
			fetch_args_from_reg(ctx, data, &rules->rules[i]);
			break;
		case ARG_RULE_MEMORY:
			fetch_args_from_memory(ctx, data, &rules->rules[i]);
			break;
		}
	}
}

static __always_inline struct runtime_stats *get_runtime_stats()
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&runtime_stats_map, &key);
}

static __always_inline __u32 current_sample_denominator()
{
	__u32 key = 0;
	struct sample_config *cfg = bpf_map_lookup_elem(&sample_config_map, &key);
	if (!cfg || cfg->denominator <= 1)
		return 1;
	return cfg->denominator;
}

static __always_inline bool should_sample(__u32 denominator)
{
	return denominator <= 1 || bpf_get_prandom_u32() % denominator == 0;
}

static __always_inline int push_event(struct event *e)
{
	int result = bpf_map_push_elem(&event_queue, e, BPF_ANY);
	struct runtime_stats *stats = get_runtime_stats();
	if (stats)
	{
		if (result == 0)
			stats->emitted_events++;
		else
			stats->dropped_events++;
	}
	return result;
}

SEC("uprobe/ent")
int ent(struct pt_regs *ctx)
{
	__u32 key = 0;
	struct event *e = bpf_map_lookup_elem(&event_buffer, &key);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));

	e->goid = get_goid();
	e->pid = get_pid();
	e->ip = ctx->ip;
	e->bp = ctx->sp - 8;
	e->caller_bp = ctx->bp;
	struct goid_key gkey = {
		.pid = e->pid,
		.goid = e->goid,
	};
	bool wanted = bpf_map_lookup_elem(&should_trace_rip, &e->ip) != 0;
	bool trace_abort = false;
	struct trace_state *state = bpf_map_lookup_elem(&should_trace_goid, &gkey);
	if (!state)
	{
		if (!wanted)
			return 0;
		// Sampling statistics are maintained regardless of whether adaptive
		// sampling is enabled. With adaptive sampling off (or a fixed rate of
		// 1) the denominator stays 1, so every root call is admitted and
		// sampled_out_roots stays 0.
		struct runtime_stats *stats = get_runtime_stats();
		__u32 denominator = current_sample_denominator();
		if (stats)
			stats->wanted_roots++;
		if (!should_sample(denominator))
		{
			if (stats)
				stats->sampled_out_roots++;
			return 0;
		}
		struct trace_state initial = {
			.root_ip = e->ip,
			.last_ip = e->ip,
			.last_bp = e->bp,
			.root_depth = 1,
			.event_count = 1,
			.sample_denominator = denominator,
		};
		if (bpf_map_update_elem(&should_trace_goid, &gkey, &initial, BPF_ANY) != 0)
		{
			if (stats)
				stats->state_insert_failures++;
			return 0;
		}
		e->sample_denominator = denominator;
		if (stats)
			stats->admitted_roots++;
		if (CONFIG.adaptive_sampling)
			e->trace_flags = TRACE_START;
	}
	else
	{
		e->sample_denominator = state->sample_denominator;
		state->event_count++;
		if (CONFIG.adaptive_sampling && state->event_count > MAX_SAMPLE_EVENTS)
		{
			e->trace_flags = TRACE_ABORT;
			trace_abort = true;
			struct runtime_stats *stats = get_runtime_stats();
			if (stats)
				stats->aborted_roots++;
		}
		bool duplicate = state->last_ip == e->ip && state->last_bp != e->caller_bp;
		if (!trace_abort && CONFIG.adaptive_sampling && wanted && state->root_ip == e->ip && !duplicate)
			state->root_depth++;
		state->last_ip = e->ip;
		state->last_bp = e->bp;
	}

	e->location = ENTPOINT;
	e->time_ns = bpf_ktime_get_ns();

	void *ra;
	ra = (void *)ctx->sp;
	bpf_probe_read_user(&e->caller_ip, sizeof(e->caller_ip), ra);

	if (!CONFIG.fetch_args)
		goto cont;

	fetch_args(ctx, e);

cont:;
	int push_result = push_event(e);
	if (trace_abort)
		bpf_map_delete_elem(&should_trace_goid, &gkey);
	return push_result;
}

SEC("uprobe/ret")
int ret(struct pt_regs *ctx)
{
	__u32 key = 0;
	struct event *e = bpf_map_lookup_elem(&event_buffer, &key);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));

	e->goid = get_goid();
	e->pid = get_pid();
	struct goid_key gkey = {
		.pid = e->pid,
		.goid = e->goid,
	};
	struct trace_state *state = bpf_map_lookup_elem(&should_trace_goid, &gkey);
	if (!state)
		return 0;
	e->sample_denominator = state->sample_denominator;
	state->last_ip = 0;

	e->location = RETPOINT;
	e->ip = ctx->ip;
	e->time_ns = bpf_ktime_get_ns();
	bool trace_abort = false;
	state->event_count++;
	if (CONFIG.adaptive_sampling && state->event_count > MAX_SAMPLE_EVENTS)
	{
		e->trace_flags = TRACE_ABORT;
		trace_abort = true;
		struct runtime_stats *stats = get_runtime_stats();
		if (stats)
			stats->aborted_roots++;
	}

	if (!CONFIG.fetch_args)
		goto cont;

	fetch_args(ctx, e);

cont:;
	bool trace_end = false;
	if (!trace_abort && CONFIG.adaptive_sampling)
	{
		__u64 *root_ip = bpf_map_lookup_elem(&should_trace_ret, &e->ip);
		if (root_ip && *root_ip == state->root_ip)
		{
			if (state->root_depth > 1)
				state->root_depth--;
			else
			{
				e->trace_flags = TRACE_END;
				trace_end = true;
			}
		}
	}
	int push_result = push_event(e);
	if (trace_end || trace_abort)
		bpf_map_delete_elem(&should_trace_goid, &gkey);
	return push_result;
}

SEC("uprobe/goroutine_exit")
int goroutine_exit(struct pt_regs *ctx)
{
	__u32 key = 0;
	struct event *e = bpf_map_lookup_elem(&event_buffer, &key);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));

	e->goid = get_goid();
	e->pid = get_pid();
	e->location = GOROUTINE_EXIT;
	struct goid_key gkey = {
		.pid = e->pid,
		.goid = e->goid,
	};
	if (!bpf_map_lookup_elem(&should_trace_goid, &gkey))
		return 0;
	bpf_map_delete_elem(&should_trace_goid, &gkey);

	return push_event(e);
}
