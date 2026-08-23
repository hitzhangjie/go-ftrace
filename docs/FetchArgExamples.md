# Fetch Rule Examples

This document collects ready-to-use `--fargs` / `--frets` rules for the common
Go argument / return-value conventions, distilled from [`testdata/args`](../testdata/args)
and [`testdata/rets`](../testdata/rets). Automatic DWARF fetch is tested against
[`testdata/auto`](../testdata/auto). For the full syntax explanation, see
[FetchArgRule.md](./FetchArgRule.md).

## Syntax reminder

```
funcname(var=(expr):type, ...)
```

- `(%ax)` — read the register value itself (integers, pointers).
- `(+N(%ax))` — read `*(AX+N)` (single dereference, e.g. struct fields).
- `(*+N(%ax))` — read `*(*(AX+N))` (double dereference, e.g. string data pointer).
- types: `s64` / `u64` (integer), `u8` (bool), `c64` (8-byte string).

## ABI register quick reference (Go 1.17+, linux/amd64)

Entry arguments and return values use the same register sequence:
`AX, BX, CX, DI, SI, R8, R9, R10, R11`.

| Kind | Layout |
| ---- | ------ |
| int / pointer | 1 word: `AX` |
| string | 2 words: data (`AX`), len (`BX`) |
| slice | 3 words: data (`AX`), len (`BX`), cap (`CX`) |
| method receiver | 1st argument (`AX`) |
| error (interface) | 2 words: itab (`AX`), data (`BX`) |
| struct value | passed on the stack — register rules do **not** apply |

## Entry arguments (`--fargs`)

### int

```bash
--fargs 'main.add(a=(%ax):s64, b=(%bx):s64)'
```

`a -> AX`, `b -> BX`.

### string

```bash
--fargs 'main.greet(name.data=(+0(%ax)):c64, name.len=(%bx):s64)'
```

`name.data` is a pointer stored in `AX`, read it directly with `(+0(%ax))` and
decode the pointed-to data as `c64`; `name.len -> BX`.

### method receiver (pointer)

```bash
--fargs 'main.(*Student).String(s.name.data=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)'
```

The receiver `*Student` is in `AX`. `s.name.data` is a string-data pointer at
`+0`, so it needs an extra dereference `(*+0(%ax))`; `len` (`+8`) and `age`
(`+16`) are plain values read directly.

### slice

```bash
--fargs 'main.sum(nums.data=(%ax):u64, nums.len=(%bx):s64, nums.cap=(%cx):s64)'
```

`nums.data -> AX`, `nums.len -> BX`, `nums.cap -> CX`.

### bool

```bash
--fargs 'main.toggle(on=(%ax):u8)'
```

A bool occupies one byte (`AL`).

## Return values (`--frets`)

### int

```bash
--frets 'main.add(result=(%ax):s64)'
```

### string

```bash
--frets 'main.makeGreeting(result.data=(%ax):u64, result.len=(%bx):s64)'
```

### pointer

```bash
--frets 'main.newStudentPtr(ptr=(%ax):u64)'
```

### error interface

```bash
--frets 'main.mayFail(err.itab=(%ax):u64, err.data=(%bx):u64)'
```

An `error` interface is two words: itab (`AX`), data (`BX`).

### multiple results

```bash
--frets 'main.divmod(quotient=(%ax):s64, remainder=(%bx):s64)'
```

### pointer to struct

```bash
--frets 'main.send(Code=(+0(%ax)):s64, Detail.itab=(+8(%ax)):u64, Detail.data=(+16(%ax)):u64)'
```

`send` returns `*MeshError` in `AX`. `Code` is a plain value at `+0`, read
directly as `(+0(%ax))`; `Detail.itab` (`+8`) and `Detail.data` (`+16`) are
also plain values.

### struct value (not supported via registers)

A struct-valued result is returned on the stack (Go ABI), not in registers, so
register-based `--frets` rules do not apply.
