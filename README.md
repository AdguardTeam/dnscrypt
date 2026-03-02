# DNSCrypt for Go

A work-in-progress modernization of [`github.com/ameshkov/dnscrypt`](https://pkg.go.dev/github.com/ameshkov/dnscrypt/v2), an implementation of the [DNSCrypt v2 protocol](https://dnscrypt.info/protocol).

- [API](#api)
    - [Client](#client)
    - [Server](#server)

## <a href="#api" id="api" name="api">API</a>

### <a href="#client" id="client" name="client">Client</a>

```go
package client

import (
    "github.com/AdguardTeam/dnscrypt/v2"
)

// AdGuard DNS stamp.
stampStr := "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"

func client() (err error) {
    // Initializing the DNSCrypt client.
    c := dnscrypt.Client{
        Net: "udp",
        Timeout: 10 * time.Second,
    }

    // Fetching and validating the server certificate.
    resolverInfo, err := c.Dial(stampStr)
    if err != nil {
        return err
    }

    // Create a DNS request.
    req := &dns.Msg{}
    req.Id = dns.Id()
    req.RecursionDesired = true
    req.Question = []dns.Question{{
        Name: "google-public-dns-a.google.com.",
        Qtype: dns.TypeA,
        Qclass: dns.ClassINET,
    }}

    // Get the DNS response.
    resp, err := c.Exchange(&req, resolverInfo)
    if err != nil {
        return err
    }

    fmt.Println(resp)

    return nil
}
```

## <a href="#server" id="server" name="server">Server</a>

```go
package server

import (
    "github.com/AdguardTeam/dnscrypt/v2"
)

func server() (err error) {
    // Prepare the test DNSCrypt server config.
    rc, err := dnscrypt.GenerateResolverConfig("my.example", nil)
    if err != nil {
        return err
    }

    cert, err := rc.CreateCert()
    if err != nil {
        return err
    }

    s := &dnscrypt.Server{
        ProviderName: rc.ProviderName,
        ResolverCert: cert,
        Handler:      dnscrypt.DefaultHandler,
    }

    // Prepare a TCP listener.
    tcpConn, err := net.ListenTCP("tcp", &net.TCPAddr{
        IP: net.IPv4zero,
        Port: 443,
    })
    if err != nil {
        return err
    }

    // Prepare a UDP listener.
    udpConn, err := net.ListenUDP("udp", &net.UDPAddr{
        IP: net.IPv4zero,
        Port: 443,
    })
    if err != nil {
        return err
    }

    // Start the server.
    go s.ServeUDP(udpConn)
    go s.ServeTCP(tcpConn)
}
```
