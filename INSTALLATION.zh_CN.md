# 安装说明

本文介绍如何安装 go-ftrace，以及相关提权设置步骤背后的原因。

## 为什么需要特殊权限

go-ftrace 会向目标进程附加 eBPF uprobe，并把 eBPF 程序加载进内核。这两步操作
都需要较高的能力（capability），例如 `CAP_BPF`、`CAP_SYS_ADMIN`、`CAP_PERFMON`，
而这些能力通常只有 `root` 用户才具备。

因此，`ftrace` 必须满足以下条件之一：

- 以 `root` 身份运行（直接运行或通过 `sudo`），或
- 通过某种安装方式，将所需的权限授予普通用户（即下文介绍的 `make install` 方式）。

## 供 root 用户安装

如果只是以 root 身份运行 `ftrace`，普通安装即可：

```bash
go install github.com/hitzhangjie/go-ftrace/cmd/ftrace@latest
```

或者，在源码目录下：

```bash
make install
```

然后以 root 身份运行：

```bash
sudo ftrace -u 'main.add' ./main
```

> 注意：`sudo` 使用的是它自己的安全 `PATH`（通常为 `/usr/sbin`、`/usr/bin` 等），
> 其中**并不包含** `$GOPATH/bin`。参见下文关于软链接的说明。

## 供非 root 用户安装

`make install` 不仅会构建二进制文件，还会对其进行相应设置，使普通用户无需
`sudo` 即可运行。具体来说，它会：

1. 构建并安装二进制文件到 `~/go/bin/ftrace`（即 `go install`）。
2. 创建软链接，使该二进制文件位于 `sudo` 的安全搜索路径上。
3. 将二进制文件的属主修改为 `root:root`。
4. 设置 setuid 位，使任何运行它的用户都能临时获得 `root` 权限（加载 eBPF 程序
   所必需）。

```bash
make install
```

完成后，非 root 用户即可直接运行：

```bash
ftrace -u 'main.add' ./main
```

### 手动等价的设置方式

如果你更倾向于手动应用这些设置，等价的命令如下：

```bash
go install github.com/hitzhangjie/go-ftrace/cmd/ftrace@latest
sudo ln -sf ~/go/bin/ftrace /usr/sbin
sudo chown root:root ~/go/bin/ftrace
sudo chmod u+s /usr/sbin/ftrace
```

## 原因说明

- **软链接到 `/usr/sbin`** —— `sudo` 会用一组安全目录（`/usr/sbin`、`/usr/bin`
  等）替换 `PATH`。如果没有这个软链接，`sudo ftrace` 将无法找到安装在
  `$GOPATH/bin` 下的二进制文件。
- **`chown root:root`** —— 只有当文件属主是它要提权到的用户（`root`）时，setuid
  位才会生效。
- **`chmod u+s`（setuid）** —— 允许非 root 用户以 root 权限运行该工具（加载
  eBPF 程序所必需），而无需授予其通用的 `sudo` 权限。

## 注意事项

- 某些文件系统会忽略 setuid 位（例如以 `nosuid` 挂载的文件系统，或某些网络
  文件系统）。如果在你的环境中 setuid 无法生效，请退回到使用 `sudo` 运行。
- 一个能够向任意进程注入 eBPF 的 setuid 二进制文件能力很强；请只在可信的机器
  上安装它，并在可能的情况下优先以 root 身份运行。
