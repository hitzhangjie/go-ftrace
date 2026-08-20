/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

var usage = `go-ftrace is bpf(2)-based ftrace(1)-like function graph tracer for Go! 

for now, only support following cases:
- OS: Linux, with support for bpf(2) and uprobe
- Arch: x86-64 little endian
- Binary: go ELF executable, non-stripped, built with non-PIE mode,
          ELF sections .symtab, .(z)debug_info are required
`

var usageLong = `go-ftrace is an eBPF(2)-based ftrace(1)-like function graph tracer for Go!

here're some tracing examples:

  example: trace a specific function: "main.add":
    ftrace -u main.add ./main

  example: trace all functions like main.add*:
    ftrace -u 'main.add*' ./main

  example: trace all functions like main.add* or main.minus*:
    ftrace -u 'main.add*' -u 'main.minus*' ./main

  example: trace a specific function and include runtime.chan* builtins:
    ftrace -u 'main.add' -u 'runtime.chan*' ./main

  example: trace a specific method of specific type:
    ftrace -u 'main.(*Student).String ./main    

  example: trace a specific method of specific type, and fetch its arguments:
    ftrace -u 'main.(*Student).String' ./main \
      --fargs 'main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)'

  example: fetch the return value of a function at its RET point:
    ftrace -u 'main.(*serviceMesh).send' ./main \
      --frets 'main.(*serviceMesh).send(Code=(+0(%ax)):s64, Detail.itab=(+8(%ax)):u64, Detail.data=(+16(%ax)):u64)'
 `

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ftrace [-u wildcards|-x|-d] <binary> [--fargs ...] [--frets ...]",
	Short: usage,
	Long:  usageLong,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if debug, _ := cmd.Flags().GetBool("debug"); debug {
			log.SetLevel(log.DebugLevel)
		}

		if len(args) < 1 {
			fmt.Println(usage)
			return errors.New("too few args")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		bin := args[0]
		excludeVendor, _ := cmd.Flags().GetBool("exclude-vendor")
		uprobeWildcards, _ := cmd.Flags().GetStringSlice("uprobe-wildcards")
		drilldown, _ := cmd.Flags().GetString("drilldown")
		trimprefix, _ := cmd.Flags().GetString("trimprefix")
		fargs, _ := cmd.Flags().GetStringArray("fargs")
		frets, _ := cmd.Flags().GetStringArray("frets")
		autoFetchArgs, _ := cmd.Flags().GetBool("fargs-auto")
		autoFetchRets, _ := cmd.Flags().GetBool("frets-auto")

		// An explicitly provided --fargs/--frets rule takes precedence over the
		// corresponding automatic DWARF derivation, so disable auto-fetch when
		// the user has explicitly set either flag.
		if cmd.Flags().Changed("fargs") {
			autoFetchArgs = false
		}
		if cmd.Flags().Changed("frets") {
			autoFetchRets = false
		}

		cluster, _ := cmd.Flags().GetBool("cluster")
		clusterInterval, _ := cmd.Flags().GetDuration("cluster-interval")
		memlockLimit, _ := cmd.Flags().GetInt64("memlock-limit")

		// positional fetch rules are kept for backward compatibility and are
		// treated as entry argument fetch rules
		fargs = append(fargs, args[1:]...)

		cfg := &Config{
			excludeVendor:   excludeVendor,
			uprobeWildcards: uprobeWildcards,
			fargs:           fargs,
			frets:           frets,
			drilldown:       drilldown,
			trimprefix:      trimprefix,
			autoFetchArgs:   autoFetchArgs,
			autoFetchRets:   autoFetchRets,
			cluster:         cluster,
			clusterInterval: clusterInterval,
		}
		tracer, err := NewTracer(bin, cfg)
		if err != nil {
			return err
		}

		if err := initLimit(memlockLimit); err != nil {
			return err
		}

		return tracer.Start()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.ftrace.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	rootCmd.Flags().BoolP("debug", "d", false, "enable debug logging")

	rootCmd.Flags().StringSliceP("uprobe-wildcards", "u", nil, "wildcards for code to add uprobes")
	rootCmd.Flags().BoolP("exclude-vendor", "x", true, "exclude vendor")
	rootCmd.Flags().StringP("drilldown", "D", "", "drill down analysis")
	rootCmd.Flags().StringP("trimprefix", "P", "", "trim filepath prefix")
	rootCmd.Flags().StringArrayP("fargs", "f", nil, "fetch arguments at function entry, e.g. 'main.(*T).M(a=(*+0(%ax)):s64)'")
	rootCmd.Flags().StringArrayP("frets", "r", nil, "fetch return values at function return, e.g. 'main.(*T).M(err=(*+0(%ax)):s64)'")
	rootCmd.Flags().BoolP("fargs-auto", "A", true, "automatically derive entry-argument fetch rules from DWARF when no explicit --fargs rule is given")
	rootCmd.Flags().BoolP("frets-auto", "R", true, "automatically derive return-value fetch rules from DWARF when no explicit --frets rule is given")
	rootCmd.Flags().BoolP("cluster", "c", false, "aggregate per-function latency distribution and top-10 return values instead of printing every call")
	rootCmd.Flags().Duration("cluster-interval", 5*time.Second, "periodic interval for printing the cumulative cluster summary (only valid with --cluster; 0 disables periodic printing and only prints on exit)")
	rootCmd.Flags().Int64("memlock-limit", 0, "maximum amount of memory (in bytes) that may be locked via RLIMIT_MEMLOCK; 0 uses the built-in default")

	rootCmd.MarkFlagRequired("uprobe-wildcards")
}

// defaultMemlockLimit caps how much memory the tracer process may lock
// (RLIMIT_MEMLOCK). Previously this was set to RLIM_INFINITY, so a bug in the
// tracer (or anything else in the process) could mlock unbounded amounts of
// memory and destabilize the whole machine. The eBPF maps used by go-ftrace are
// only a few MiB in total, so this cap is generous while still bounding the
// worst-case impact.
//
// Note: on kernels >= 5.11 BPF map/program memory is accounted via memcg and no
// longer charged against RLIMIT_MEMLOCK, so on modern kernels this limit mainly
// guards mlock(2); on older kernels it also bounds BPF object memory.
const defaultMemlockLimit = 128 << 20 // 128 MiB

func initLimit(memlockLimit int64) error {
	if memlockLimit <= 0 {
		memlockLimit = defaultMemlockLimit
	}

	rlimit := syscall.Rlimit{
		Cur: uint64(memlockLimit),
		Max: uint64(memlockLimit),
	}
	if err := syscall.Setrlimit(unix.RLIMIT_MEMLOCK, &rlimit); err != nil {
		return fmt.Errorf("setrlimit RLIMIT_MEMLOCK: %w", err)
	}
	rlimit = syscall.Rlimit{
		Cur: 1048576,
		Max: 1048576,
	}
	if err := syscall.Setrlimit(unix.RLIMIT_NOFILE, &rlimit); err != nil {
		return fmt.Errorf("setrlimit RLIMIT_NOFILE: %w", err)
	}
	return nil
}
