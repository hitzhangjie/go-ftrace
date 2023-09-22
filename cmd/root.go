/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"errors"
	"fmt"
	"os"
	"syscall"

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

  example: trace a specific method of specific type, and fetch its arguemnts:
    ftrace -u 'main.(*Student).String' ./main \
      'main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)'
 `

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ftrace [-u wildcards|-x|-d] <binary> [fetch]",
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
		fetch := args[1:]
		excludeVendor, _ := cmd.Flags().GetBool("exclude-vendor")
		uprobeWildcards, _ := cmd.Flags().GetStringSlice("uprobe-wildcards")

		tracer, err := NewTracer(bin, excludeVendor, uprobeWildcards, fetch)
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
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.ftrace.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	rootCmd.Flags().BoolP("debug", "d", false, "enable debug logging")
	rootCmd.Flags().BoolP("exclude-vendor", "x", true, "exclude vendor")
	rootCmd.Flags().StringSliceP("uprobe-wildcards", "u", nil, "wildcards for code to add uprobes")

	rootCmd.MarkFlagRequired("uprobe-wildcards")
}

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
