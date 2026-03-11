package dnscrypt

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func BenchmarkServeUDP(b *testing.B) {
	benchmarkServe(b, ProtoUDP)

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/dnscrypt
	//	cpu: Apple M4 Pro
	//	BenchmarkServeUDP-14    	    9333	    126311 ns/op	    6681 B/op	      61 allocs/op
	//	PASS
	//	ok  	github.com/AdguardTeam/dnscrypt	2.052s
}

func BenchmarkServeTCP(b *testing.B) {
	benchmarkServe(b, ProtoTCP)
	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/dnscrypt
	//	cpu: Apple M4 Pro
	//	BenchmarkServeTCP-14    	   10113	    115749 ns/op	    5568 B/op	      65 allocs/op
}

func benchmarkServe(b *testing.B, proto Proto) {
	srv := newTestServer(b, &testHandler{})
	b.Cleanup(func() {
		err := srv.Close()
		require.NoError(b, err)
	})

	client := &Client{
		Timeout: 1 * time.Second,
		Proto:   proto,
	}

	serverAddr := fmt.Sprintf("127.0.0.1:%d", srv.UDPAddr().Port)
	if proto == ProtoTCP {
		serverAddr = fmt.Sprintf("127.0.0.1:%d", srv.TCPAddr().Port)
	}

	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: serverAddr,
		ServerPk:      srv.resolverPk,
		ProviderName:  srv.server.ProviderName,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}
	ri, err := client.DialStamp(stamp)
	require.NoError(b, err)
	require.NotNil(b, ri)

	conn, err := net.Dial(string(proto), stamp.ServerAddrStr)
	require.NoError(b, err)

	var resp *dns.Msg

	b.ReportAllocs()
	for b.Loop() {
		m := createTestMessage()

		resp, err = client.ExchangeConn(conn, m, ri)
		require.NoError(b, err)
		assertTestMessageResponse(b, resp)
	}
}
