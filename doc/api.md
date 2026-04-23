# Programming interface

DNSCrypt provides a Go API for both client and server implementations.

## Contents

- [Client](#client)
- [Server](#server)

## <a href="#client" id="client" name="client">Client</a>

```go
func client() (err error) {
    // DNSCrypt server stamp.
    stampStr := "sdns://..."

    // Initializing the DNSCrypt client.
    c := dnscrypt.NewClient(&dnscrypt.ClientConfig{
        Proto: dnscrypt.ProtoUDP,
    })

    timeout := 10 * time.Second

    // NOTE: The context is used to set the client timeout.
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()

    // Fetching and validating the server certificate.
    resolverInfo, err := c.DialContext(ctx, stampStr)
    if err != nil {
        return err
    }

    // Create a DNS request.
    req := &dns.Msg{}
    req.Id = dns.Id()
    req.RecursionDesired = true
    req.Question = []dns.Question{{
        Name:   "google-public-dns-a.google.com.",
        Qtype:  dns.TypeA,
        Qclass: dns.ClassINET,
    }}

    // Get the DNS response.
    resp, err := c.ExchangeContext(ctx, req, resolverInfo)
    if err != nil {
        return err
    }

    fmt.Println(resp)

    return nil
}
```

## <a href="#server" id="server" name="server">Server</a>

```go
func server() (err error) {
    // Prepare the test DNSCrypt server config.
    rc, err := dnscrypt.GenerateResolverConfig("example.org", nil, 0)
    if err != nil {
        return err
    }

    cert, err := rc.NewCert()
    if err != nil {
        return err
    }

    s, err := dnscrypt.NewServer(&dnscrypt.ServerConfig{
        ProviderName: rc.ProviderName,
        ResolverCert: cert,
    })
    if err != nil {
        return err
    }

    // Prepare a TCP listener.
    tcpConn, err := net.ListenTCP(string(dnscrypt.ProtoTCP), &net.TCPAddr{IP: net.IPv4zero})
    if err != nil {
        return err
    }

    // Prepare a UDP listener.
    udpConn, err := net.ListenUDP(string(dnscrypt.ProtoUDP), &net.UDPAddr{IP: net.IPv4zero})
    if err != nil {
        return err
    }

    // Start the server.
    go s.ServeUDP(context.Background(), udpConn)
    go s.ServeTCP(context.Background(), tcpConn)

    return nil
}
```
