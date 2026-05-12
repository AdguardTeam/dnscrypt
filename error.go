package dnscrypt

import "github.com/AdguardTeam/golibs/errors"

const (
	// ErrTooShort is returned when the DNS query is shorter than possible.
	ErrTooShort errors.Error = "message is too short"

	// ErrQueryTooLarge is returned when the DNS query is larger than max
	// allowed size.
	ErrQueryTooLarge errors.Error = "dnscrypt query is too large"

	// ErrESVersion is returned when the cert contains unsupported es-version.
	ErrESVersion errors.Error = "unsupported es-version"

	// ErrInvalidDate is returned when the cert is not valid for the current
	// time.
	ErrInvalidDate errors.Error = "cert has invalid ts-start or ts-end"

	// ErrInvalidCertSignature is returned when the cert has invalid signature.
	ErrInvalidCertSignature errors.Error = "cert has invalid signature"

	// ErrInvalidQuery is returned when it failed to decrypt a DNSCrypt query.
	ErrInvalidQuery errors.Error = "dnscrypt query is invalid and cannot be decrypted"

	// ErrInvalidClientMagic is returned when client-magic does not match.
	ErrInvalidClientMagic errors.Error = "dnscrypt query contains invalid client magic"

	// ErrInvalidResolverMagic is returned when server-magic does not match.
	ErrInvalidResolverMagic errors.Error = "dnscrypt response contains invalid resolver magic"

	// ErrInvalidResponse is returned when it failed to decrypt a DNSCrypt
	// response.
	ErrInvalidResponse errors.Error = "dnscrypt response is invalid and cannot be decrypted"

	// ErrInvalidPadding is returned when it failed to unpad a query.
	ErrInvalidPadding errors.Error = "invalid padding"

	// ErrInvalidDNSStamp is returned when an invalid DNS stamp is provided.
	ErrInvalidDNSStamp errors.Error = "invalid stamp"

	// ErrFailedToFetchCert is returned when it failed to fetch DNSCrypt
	// certificate.
	ErrFailedToFetchCert errors.Error = "failed to fetch dnscrypt certificate"

	// ErrCertTooShort is returned when it failed to deserialize cert, too
	// short.
	ErrCertTooShort errors.Error = "cert is too short"

	// ErrCertMagic is returned when an invalid cert magic is encountered.
	ErrCertMagic errors.Error = "invalid cert magic"

	// ErrServerConfig is returned when it failed to start the DNSCrypt server
	// due to invalid configuration.
	ErrServerConfig errors.Error = "invalid server configuration"

	// ErrServerNotStarted is returned if there's nothing to shutdown.
	ErrServerNotStarted errors.Error = "server is not started"

	// ErrServerAlreadyStarted is returned if [Server.Start] is being called on
	// a server that is already started.
	ErrServerAlreadyStarted errors.Error = "server is already started"
)
