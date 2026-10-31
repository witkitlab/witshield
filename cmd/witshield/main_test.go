package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestEveryCommandRecoversBeforeDispatch(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--help"}, {"check", "--unknown"}, {"unknown"}, {"apt-plan-guard"}} {
		var out, errOut bytes.Buffer
		recovered := false
		run(context.Background(), args, strings.NewReader(""), &out, &errOut, func(context.Context, io.Writer) error {
			if out.Len() != 0 || errOut.Len() != 0 {
				t.Fatal("dispatch ran before recovery")
			}
			recovered = true
			return nil
		})
		if !recovered {
			t.Fatalf("missing recovery for %v", args)
		}
	}
}
func TestRecoveryFailureStopsEveryCommand(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"check", "--fix"}} {
		var out, errOut bytes.Buffer
		code := run(context.Background(), args, strings.NewReader(""), &out, &errOut, func(context.Context, io.Writer) error { return errors.New("protected fixture rejected") })
		if code != 2 || out.Len() != 0 || !strings.Contains(errOut.String(), "恢复前不会继续") {
			t.Fatalf("code=%d out=%s err=%s", code, &out, &errOut)
		}
	}
}
