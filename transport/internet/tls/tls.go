// +build !confonly

package tls

import (
	"crypto/tls"

	"v2ray.com/core/common/buf"
	"v2ray.com/core/common/net"

	utls "github.com/refraction-networking/utls"
)

//go:generate errorgen

var (
	_ buf.Writer = (*conn)(nil)
)

type conn struct {
	*tls.Conn
}

func (c *conn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	mb = buf.Compact(mb)
	mb, err := buf.WriteMultiBuffer(c, mb)
	buf.ReleaseMulti(mb)
	return err
}

func (c *conn) HandshakeAddress() net.Address {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.Conn.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	return net.ParseAddress(state.ServerName)
}

// Client initiates a TLS client handshake on the given connection.
func Client(c net.Conn, config *tls.Config) net.Conn {
	tlsConn := tls.Client(c, config)
	client := &conn{Conn: tlsConn}
	if err := client.Handshake(); err != nil {
		return nil
	}
	return client
}

func copyConfig(c *tls.Config) *utls.Config {
	return &utls.Config{
		ServerName:         c.ServerName,
		InsecureSkipVerify: c.InsecureSkipVerify,
	}
}

func UClient(c net.Conn, config *tls.Config) net.Conn {
	uConfig := copyConfig(config)
	client := utls.UClient(c, uConfig, utls.HelloChrome_Auto)
	if err := client.Handshake(); err != nil {
		return nil
	}
	return client
}

// Server initiates a TLS server handshake on the given connection.
func Server(c net.Conn, config *tls.Config) net.Conn {
	tlsConn := tls.Server(c, config)
	return &conn{Conn: tlsConn}
}
