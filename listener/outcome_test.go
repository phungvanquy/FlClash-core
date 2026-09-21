package listener

import (
	"errors"
	"net"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
)

func TestMixedListenerReportsBindFailureAndRecovery(t *testing.T) {
	previousLan, previousBind := AllowLan(), BindAddress()
	SetAllowLan(false)
	SetBindAddress("*")
	t.Cleanup(func() {
		StopListener()
		SetAllowLan(previousLan)
		SetBindAddress(previousBind)
	})
	blocked, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	port := blocked.LocalAddr().(*net.UDPAddr).Port
	if err := ReCreateMixed(port, nil); err == nil {
		t.Fatal("UDP bind failure was reported as success")
	}
	StopListener()
	if err := blocked.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ReCreateMixed(port, nil); err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	if GetPorts().MixedPort != port {
		t.Fatal("recovered listener is missing")
	}
}

type failedInbound struct {
	C.InboundListener
	failure error
}

func (f *failedInbound) Listen(C.Tunnel) error { return f.failure }

func TestNamedListenerReturnsCreationFailure(t *testing.T) {
	failure := errors.New("listener creation denied")
	if err := PatchInboundListeners(map[string]C.InboundListener{
		"failed": &failedInbound{failure: failure},
	}, nil, true); !errors.Is(err, failure) {
		t.Fatalf("listener result = %v", err)
	}
}

func TestTunnelReportsBindFailureAndCanStop(t *testing.T) {
	blocked, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	defer PatchTunnel(nil, nil)
	config := []LC.Tunnel{{Network: []string{"tcp"}, Address: blocked.Addr().String(), Target: "127.0.0.1:9", Proxy: "DIRECT"}}
	if err := PatchTunnel(config, nil); err == nil {
		t.Fatal("tunnel bind failure was reported as success")
	}
	_ = blocked.Close()
	if err := PatchTunnel(config, nil); err != nil {
		t.Fatal(err)
	}
	if len(tunnelTCPListeners) != 1 {
		t.Fatal("tunnel was not created")
	}
	if err := PatchTunnel(nil, nil); err != nil || len(tunnelTCPListeners) != 0 {
		t.Fatalf("tunnel stop failed: %v", err)
	}
}
