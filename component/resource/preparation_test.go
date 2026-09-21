package resource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	P "github.com/metacubex/mihomo/constant/provider"
)

type stagedVehicle struct {
	path   string
	reads  int
	writes int
}

func (v *stagedVehicle) Path() string        { return v.path }
func (v *stagedVehicle) Url() string         { return "https://example.invalid/provider" }
func (v *stagedVehicle) Proxy() string       { return "" }
func (v *stagedVehicle) Type() P.VehicleType { return P.HTTP }
func (v *stagedVehicle) Read(context.Context, utils.HashType) ([]byte, utils.HashType, error) {
	v.reads++
	return nil, utils.HashType{}, errors.New("unexpected remote read")
}
func (v *stagedVehicle) Write([]byte) error { v.writes++; return nil }

func TestPreparedFetcherRetainsValidatedBytesUntilActivation(t *testing.T) {
	v := &stagedVehicle{path: filepath.Join(t.TempDir(), "provider.yaml")}
	if err := os.WriteFile(v.path, []byte("validated"), 0600); err != nil {
		t.Fatal(err)
	}
	parsed, updated := 0, ""
	f := NewFetcher("candidate", 0, v, nil, func(buf []byte) (string, error) {
		parsed++
		return string(buf), nil
	}, func(value string) { updated = value })
	t.Cleanup(func() { _ = f.Close() })
	value, err := f.Prepare()
	if err != nil || value != "validated" || updated != value {
		t.Fatalf("prepare: %q %v", value, err)
	}
	if f.started || f.watcher != nil {
		t.Fatal("preparation started maintenance")
	}
	if err := os.WriteFile(v.path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	value, err = f.Initial()
	if err != nil || value != "validated" || parsed != 1 {
		t.Fatalf("activation reparsed: %q %v (%d)", value, err, parsed)
	}
	if v.reads != 0 || v.writes != 0 {
		t.Fatal("preparation/activation performed remote or cache writes")
	}
	if _, err := f.Initial(); err != nil {
		t.Fatal(err)
	}
}

func TestFailedPreparationDoesNotFetchOrStartMaintenance(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "invalid"}[invalid], func(t *testing.T) {
			v := &stagedVehicle{path: filepath.Join(t.TempDir(), "provider.yaml")}
			if invalid {
				if err := os.WriteFile(v.path, []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			updates := 0
			f := NewFetcher("candidate", 0, v, nil, func([]byte) (string, error) {
				return "", errors.New("invalid content")
			}, func(string) { updates++ })
			t.Cleanup(func() { _ = f.Close() })
			if _, err := f.Prepare(); err == nil {
				t.Fatal("expected rejection")
			}
			if f.started || f.watcher != nil || updates != 0 || v.reads != 0 || v.writes != 0 {
				t.Fatal("failed preparation had side effects")
			}
		})
	}
}

func TestDiscardedFetcherCannotActivate(t *testing.T) {
	v := &stagedVehicle{path: filepath.Join(t.TempDir(), "provider.yaml")}
	if err := os.WriteFile(v.path, []byte("candidate"), 0600); err != nil {
		t.Fatal(err)
	}
	f := NewFetcher("candidate", 0, v, nil, func(buf []byte) (string, error) { return string(buf), nil }, nil)
	if _, err := f.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Initial(); err == nil {
		t.Fatal("discarded provider activated")
	}
	if _, err := f.Prepare(); err == nil {
		t.Fatal("discarded provider prepared")
	}
}

func TestPreparedFileProviderNeverWatchesOrMutatesCommittedContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider.yaml")
	if err := os.WriteFile(path, []byte("committed"), 0600); err != nil {
		t.Fatal(err)
	}
	updates := 0
	f := NewFetcher("candidate", 0, NewFileVehicle(path), nil, func(buf []byte) (string, error) { return string(buf), nil }, func(string) { updates++ })
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.Prepare(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Initial(); err != nil {
		t.Fatal(err)
	}
	if f.watcher != nil {
		t.Fatal("immutable provider started a file watcher")
	}
	if _, _, err := f.Update(); !errors.Is(err, ErrManagedRefresh) {
		t.Fatalf("native update = %v", err)
	}
	if _, _, err := f.SideUpdate([]byte("changed")); !errors.Is(err, ErrManagedRefresh) {
		t.Fatalf("native side-load = %v", err)
	}
	buf, err := os.ReadFile(path)
	if err != nil || string(buf) != "committed" || updates != 1 {
		t.Fatal("native update mutated committed content")
	}
}
