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
		hideUnexported, _ := cmd.Flags().GetBool("hide-unexported")

		// An explicitly provided --fargs/--frets rule takes precedence over the
		// corresponding automatic DWARF derivation, so disable auto-fetch when
		// the user has explicitly set either flag.
		if cmd.Flags().Changed("fargs") {
			autoFetchArgs = false
		}
		if cmd.Flags().Changed("frets") {
			autoFetchRets = false
		}

		aggregate, _ := cmd.Flags().GetBool("aggregate")
		aggregateInterval, _ := cmd.Flags().GetDuration("aggregate-interval")
		memoryLimitMB, _ := cmd.Flags().GetUint64("memory-limit")
		adaptiveSample, _ := cmd.Flags().GetBool("adaptive-sample")

		// positional fetch rules are kept for backward compatibility and are
		// treated as entry argument fetch rules
		fargs = append(fargs, args[1:]...)

		cfg := &Config{
			excludeVendor:     excludeVendor,
			uprobeWildcards:   uprobeWildcards,
			fargs:             fargs,
			frets:             frets,
			drilldown:         drilldown,
			trimprefix:        trimprefix,
			autoFetchArgs:     autoFetchArgs,
			autoFetchRets:     autoFetchRets,
			hideUnexported:    hideUnexported,
			aggregate:         aggregate,
			aggregateInterval: aggregateInterval,
			memoryLimitMB:     memoryLimitMB,
			adaptiveSample:    adaptiveSample,
		}
		tracer, err := NewTracer(bin, cfg)
		if err != nil {
			return err
		}

		if err := initLimit(); err != nil {
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
	log.SetFormatter(&log.TextFormatter{
		DisableLevelTruncation: true,
		FullTimestamp:          true,
		TimestampFormat:        "15:04:05.000",
	})

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.ftrace.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	rootCmd.Flags().BoolP("debug", "d", false, "enable debug logging")

	rootCmd.Flags().StringSliceP("uprobe-wildcards", "u", nil, "functions to add uprobes")
	rootCmd.Flags().BoolP("exclude-vendor", "x", true, "exclude vendor packages")
	rootCmd.Flags().StringP("drilldown", "D", "", "drill down into a function")
	rootCmd.Flags().StringP("trimprefix", "P", "", "trim filepath prefix in output")
	rootCmd.Flags().StringArrayP("fargs", "f", nil, "fetch entry arguments, e.g. 'main.(*T).M(a=(*+0(%ax)):s64)'")
	rootCmd.Flags().StringArrayP("frets", "r", nil, "fetch return values, e.g. 'main.(*T).M(err=(*+0(%ax)):s64)'")
	rootCmd.Flags().BoolP("fargs-auto", "A", true, "derive entry-argument rules from DWARF when no --fargs is given")
	rootCmd.Flags().BoolP("frets-auto", "R", true, "derive return-value rules from DWARF when no --frets is given")
	rootCmd.Flags().Bool("hide-unexported", false, "omit unexported struct fields when printing auto-fetched values")
	rootCmd.Flags().Bool("aggregate", false, "aggregate per-function latency and top-10 return values instead of printing every call")
	rootCmd.Flags().Duration("aggregate-interval", 3*time.Second, "interval for periodic aggregate summary; 0 prints only on exit")
	rootCmd.Flags().Uint64("memory-limit", 256, "Go heap target (MiB) for adaptive backpressure")
	rootCmd.Flags().Bool("adaptive-sample", true, "dynamically reduce sampling near --memory-limit; false collects every root call")

	rootCmd.MarkFlagRequired("uprobe-wildcards")
}

// initLimit removes any cap on locked memory (RLIMIT_MEMLOCK) and raises
// RLIMIT_NOFILE to accommodate a large number of probe links.
func initLimit() error {
	rlimit := syscall.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
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
