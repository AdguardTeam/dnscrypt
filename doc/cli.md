# DNSCrypt command-line interface

Besides the [programming interface](api.md), DNSCrypt has command-line interface.

## Contents

- [Server](#server)
    - [Options](#server-opts)
    - [Example](#server-example)
- [Lookup](#lookup)
    - [Options](#lookup-opts)
    - [Example](#lookup-example)
- [Generate](#generate)
    - [Options](#generate-opts)
    - [Example](#generate-example)
- [Convert](#convert)
    - [Options](#convert-opts)
    - [Example](#convert-example)
- [Common options](#common-opts)
    - [Help](#common-opts-help)
    - [Verbose](#common-opts-verbose)
    - [Version](#common-opts-version)

## <a href="#server" id="server" name="server">Server</a>

Starts DNSCrypt server with specified parameters. Config can be generated using [generate](#generate) or [convert](#convert) commands.

### <a href="#server-opts" id="server-opts" name="server-opts">Options</a>

- `-c/--config <path>`: Path to the server configuration file.

    **Default:** `config.yaml`

- `-f/--forward <addr>`: Default upstream for server.

    **Default:** `94.140.14.140:53`

- `-l/--listen <addr>`: Server listening addresses.

    **Default:** `0.0.0.0:443`

- `-t/--timeout <duration>`: Timeout for server to request upstream.

    **Default:** `10s`

### <a href="#server-example" id="server-example" name="server-example">Example</a>

```bash
dnscrypt server --config config.yaml --listen 0.0.0.0:443 --listen 0.0.0.0:8888 --forward 8.8.8.8:53 --timeout 5s
```

This server can be requested using [lookup](#lookup) command, or [dnslookup](https://github.com/ameshkov/dnslookup) tool. For DNSCrypt stamp generation see https://dnscrypt.info/stamps.

## <a href="#lookup" id="lookup" name="lookup">Lookup</a>

Performs DNS lookup via DNSCrypt using stamp or raw server parameters.

### <a href="#lookup-opts" id="lookup-opts" name="lookup-opts">Options</a>

- `-a/--addr <addr>`: Resolver address (IP[:port]).

    **Default:** No default value. If stamp is not specified, this option is **required.**

- `-d/--domain <domain>`: Domain to resolve.

    **Default:** No default value, option is **required.**

- `-n/--network <proto>`: Network protocol (tcp/udp).

    **Default:** `udp`

- `-pk/--public-key <key>`: DNSCrypt resolver public key.

    **Default:** No default value. If stamp is not specified, this option is **required.**

- `-pn/--provider-name <name>`: DNSCrypt provider name.

    **Default:** No default value. If stamp is not specified, this option is **required.**

- `-s/--stamp <stamp>`: DNSCrypt resolver stamp.

    **Default:** No default value.

- `-t/--type <type>`: DNS query type.

    **Default:** `A`

### <a href="#lookup-example" id="lookup-example" name="lookup-example">Example</a>

```bash
dnscrypt lookup --domain example.org --stamp sdns://...

dnscrypt lookup --domain example.org --public-key <key> --provider-name 2.dnscrypt-cert.example.org --addr 1.2.3.4:443
```

## <a href="#generate" id="generate" name="generate">Generate</a>

Generates DNSCrypt resolver config.

### <a href="#generate-opts" id="generate-opts" name="generate-opts">Options</a>

- `-o/--out <path>`: Output file path.

    **Default:** `config.yaml`

- `-pk/--private-key <key>`: Server hex-encoded private key.

    **Default:** No default value. If option is not specified, new private key will be generated.

- `-pn/--provider-name <name>`: DNSCrypt provider name.

    **Default:** No default value, option is **required.**

- `-t/--ttl <duration>`: Certificate time-to-live.

    **Default:** `8760h`.

### <a href="#generate-example" id="generate-example" name="generate-example">Example</a>

```bash
dnscrypt generate --provider-name 2.dnscrypt-cert.example.org --out config.yaml

dnscrypt generate --provider-name 2.dnscrypt-cert.example.org --private-key <hex-key> --out config.yaml
```

## <a href="#convert" id="convert" name="convert">Convert</a>

Generates DNSCrypt resolver config from keys generated with [dnscrypt-wrapper](https://github.com/cofyc/dnscrypt-wrapper).

### <a href="#convert-opts" id="convert-opts" name="convert-opts">Options</a>

- `-o/--out <path>`: Output file path.

    **Default:** `config.yaml`

- `-pk/--private-key <path>`: Path to file with server private key.

    **Default:** No default value, option is **required.**

- `-pn/--provider-name <name>`: DNSCrypt provider name.

    **Default:** No default value, option is **required.**

- `-r/--resolver-secret <path>`: Path to file with short-term privacy key.

    **Default:** No default value, option is **required.**

- `-t/--ttl <duration>`: Certificate time-to-live.

    **Default:** `8760h`.

### <a href="#convert-example" id="convert-example" name="convert-example">Example</a>

```bash
dnscrypt convert --provider-name 2.dnscrypt-cert.example.org --private-key secret.key --resolver-secret crypt_secret.key --out config.yaml
```

## <a href="#common-opts" id="common-opts" name="common-opts">Common options</a>

### <a href="#common-opts-help" id="common-opts-help" name="common-opts-help">Help</a>

`-h/--help`: makes DNSCrypt print out a help message to standard output and exit with a success status-code.

### <a href="#common-opts-verbose" id="common-opts-verbose" name="common-opts-verbose">Verbose</a>

`-v/--verbose`: Enables verbose logging.

### <a href="#common-opts-version" id="common-opts-version" name="common-opts-version">Version</a>

`--version`: makes DNSCrypt print out the version of the application to standard output and exit with a success status-code.
