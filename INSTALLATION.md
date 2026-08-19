# Installation

This document explains how to install go-ftrace and the rationale behind the
privilege-related setup steps.

## Why special privileges are needed

go-ftrace attaches eBPF uprobes to a target process and loads eBPF programs into
the kernel. Both operations require elevated capabilities (e.g. `CAP_BPF`,
`CAP_SYS_ADMIN`, `CAP_PERFMON`) that are normally only available to `root`.

Therefore, `ftrace` must either:

- be run as `root` (directly or via `sudo`), or
- be installed in a way that grants the required privileges to ordinary users
  (the `make install` approach described below).

## Installing for root

If you only run `ftrace` as root, a plain install is enough:

```bash
go install github.com/hitzhangjie/go-ftrace/cmd/ftrace@latest
```

or, from a source checkout:

```bash
make install
```

Then run it as root:

```bash
sudo ftrace -u 'main.add' ./main
```

> Note: `sudo` uses its own secure `PATH` (typically `/usr/sbin`, `/usr/bin`,
> ...), which does **not** include `$GOPATH/bin`. See the symlink note below.

## Installing for non-root users

`make install` does more than build the binary — it also sets it up so that
ordinary users can run it without `sudo`. Specifically, it:

1. Builds and installs the binary to `~/go/bin/ftrace` (`go install`).
2. Creates a symlink so the binary is on `sudo`'s secure search path.
3. Changes the binary's owner to `root:root`.
4. Sets the setuid bit, so that any user who runs it temporarily gains `root`
   privileges (needed to load eBPF programs).

```bash
make install
```

After that, a non-root user can simply run:

```bash
ftrace -u 'main.add' ./main
```

### Manual equivalent

If you prefer to apply the settings by hand, the equivalent commands are:

```bash
go install github.com/hitzhangjie/go-ftrace/cmd/ftrace@latest
sudo ln -sf ~/go/bin/ftrace /usr/sbin
sudo chown root:root ~/go/bin/ftrace
sudo chmod u+s /usr/sbin/ftrace
```

## Rationale

- **Symlink to `/usr/sbin`** — `sudo` replaces `PATH` with a secure set of
  directories (`/usr/sbin`, `/usr/bin`, ...). Without the symlink, `sudo ftrace`
  cannot find the binary installed under `$GOPATH/bin`.
- **`chown root:root`** — the setuid bit only takes effect when the file is
  owned by the user it elevates to (`root`).
- **`chmod u+s` (setuid)** — lets a non-root user run the tool with root
  privileges, which is required to load eBPF programs, without granting general
  `sudo` access.

## Caveats

- The setuid bit is ignored by some filesystems (e.g. those mounted with
  `nosuid`, or some network filesystems). If setuid does not work in your
  environment, fall back to running via `sudo`.
- A setuid binary that can inject eBPF into arbitrary processes is powerful;
  install it only on machines you trust, and prefer running as root when
  possible.
