package config

import (
	"errors"
	"reflect"
	"testing"
)

type preparedResource struct {
	name   string
	closed *[]string
}

func (r *preparedResource) Close() error {
	*r.closed = append(*r.closed, r.name)
	return errors.New(r.name)
}

func TestPartialCandidateCleanupReleasesEveryResourceOnce(t *testing.T) {
	var closed []string
	p := &parseContext{detached: true}
	p.own(&preparedResource{name: "first", closed: &closed})
	p.own(&preparedResource{name: "second", closed: &closed})
	p.deferActivation(func() { t.Error("discard ran an activation hook") })
	if err := p.close(); err == nil {
		t.Fatal("cleanup errors were lost")
	}
	if !reflect.DeepEqual(closed, []string{"second", "first"}) {
		t.Fatalf("cleanup order = %v", closed)
	}
	if err := p.close(); err != nil || len(closed) != 2 || len(p.activation) != 0 {
		t.Fatal("cleanup was not idempotent")
	}
}
