package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestResolveExplicitCriticalDays_DefaultNotConsideredExplicit(t *testing.T) {
	root := &cobra.Command{Use: "root"}
	child := &cobra.Command{Use: "child"}
	child.Flags().Int("critical-days", 90, "")
	root.AddCommand(child)

	if err := child.ParseFlags([]string{}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}

	if _, ok := resolveExplicitCriticalDays(child); ok {
		t.Fatalf("expected no explicit critical-days override")
	}
}

func TestResolveExplicitCriticalDays_LocalFlag(t *testing.T) {
	root := &cobra.Command{Use: "root"}
	child := &cobra.Command{Use: "child"}
	child.Flags().Int("critical-days", 90, "")
	root.AddCommand(child)

	if err := child.ParseFlags([]string{"--critical-days", "120"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}

	v, ok := resolveExplicitCriticalDays(child)
	if !ok {
		t.Fatalf("expected explicit critical-days override")
	}
	if v != 120 {
		t.Fatalf("expected critical-days=120, got %d", v)
	}
}

func TestResolveExplicitCriticalDays_InheritedFlag(t *testing.T) {
	root := &cobra.Command{Use: "root"}
	child := &cobra.Command{Use: "child"}
	grandchild := &cobra.Command{Use: "grandchild"}

	root.PersistentFlags().Int("critical-days", 90, "")
	root.AddCommand(child)
	child.AddCommand(grandchild)

	if err := grandchild.ParseFlags([]string{"--critical-days", "45"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}

	v, ok := resolveExplicitCriticalDays(grandchild)
	if !ok {
		t.Fatalf("expected explicit inherited critical-days override")
	}
	if v != 45 {
		t.Fatalf("expected critical-days=45, got %d", v)
	}
}
