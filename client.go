package socks

import (
	"errors"
	"io"
	"net"
	"strconv"
)

const socks5Version = 5

const (
	socks5AuthNone     = 0
	socks5AuthPassword = 2
)

const socks5Connect = 1

const (
	socks5IP4    = 1
	socks5Domain = 3
	socks5IP6    = 4
)

var socks5Errors = []string{
	"",
	"general failure",
	"connection forbidden",
	"network unreachable",
	"host unreachable",
	"connection refused",
	"TTL expired",
	"command not supported",
	"address type not supported",
}

// Auth send auth command to server
//func Auth(conn net.Conn) error {
//buf := make([]byte, 0)

//buf = append(buf, socks5Version)
//if len(s.user) > 0 && len(s.user) < 256 && len(s.password) < 256 {
//buf = append(buf, 2 /* num auth methods */, socks5AuthNone, socks5AuthPassword)
//} else {
//buf = append(buf, 1 /* num auth methods */, socks5AuthNone)
//}

//if _, err := conn.Write(buf); err != nil {
//return errors.New("proxy: failed to write greeting to SOCKS5 proxy at " + s.addr + ": " + err.Error())
//}

//if _, err := io.ReadFull(conn, buf[:2]); err != nil {
//return errors.New("proxy: failed to read greeting from SOCKS5 proxy at " + s.addr + ": " + err.Error())
//}
//if buf[0] != 5 {
//return errors.New("proxy: SOCKS5 proxy at " + s.addr + " has unexpected version " + strconv.Itoa(int(buf[0])))
//}
//if buf[1] == 0xff {
//return errors.New("proxy: SOCKS5 proxy at " + s.addr + " requires authentication")
//}

//// See RFC 1929
//if buf[1] == socks5AuthPassword {
//buf = buf[:0]
//buf = append(buf, 1 /* password protocol version */)
//buf = append(buf, uint8(len(s.user)))
//buf = append(buf, s.user...)
//buf = append(buf, uint8(len(s.password)))
//buf = append(buf, s.password...)

//if _, err := conn.Write(buf); err != nil {
//return errors.New("proxy: failed to write authentication request to SOCKS5 proxy at " + s.addr + ": " + err.Error())
//}

//if _, err := io.ReadFull(conn, buf[:2]); err != nil {
//return errors.New("proxy: failed to read authentication reply from SOCKS5 proxy at " + s.addr + ": " + err.Error())
//}

//if buf[1] != 0 {
//return errors.New("proxy: SOCKS5 proxy at " + s.addr + " rejected username/password")
//}
//}
//}

// Connect takes an existing connection to a socks5 proxy server,
// and commands the server to extend that connection to target,
// which must be a canonical address with a host and port.
func Connect(conn net.Conn, target *AddrSpec, noReply bool) error {
	var buf []byte

	// the size here is just an estimate
	buf = append(buf, socks5Version, socks5Connect, 0 /* reserved */)

	if len(target.IP) != 0 {
		if ip4 := target.IP.To4(); ip4 != nil {
			buf = append(buf, socks5IP4)
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, socks5IP6)
			buf = append(buf, target.IP...)
		}
	} else {
		if len(target.FQDN) > 255 {
			return errors.New("proxy: destination host name too long: " + target.FQDN)
		}
		buf = append(buf, socks5Domain)
		buf = append(buf, byte(len(target.FQDN)))
		buf = append(buf, target.FQDN...)
	}
	port := target.Port
	buf = append(buf, byte(port>>8), byte(port))

	if _, err := conn.Write(buf); err != nil {
		return errors.New("proxy: failed to write connect request to SOCKS5 proxy at " + conn.RemoteAddr().String() + ": " + err.Error())
	}

	if noReply {
		return nil
	}

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return errors.New("proxy: failed to read connect reply from SOCKS5 proxy at " + conn.RemoteAddr().String() + ": " + err.Error())
	}

	failure := "unknown error"
	if int(buf[1]) < len(socks5Errors) {
		failure = socks5Errors[buf[1]]
	}

	if len(failure) > 0 {
		return errors.New("proxy: SOCKS5 proxy at " + conn.RemoteAddr().String() + " failed to connect: " + failure)
	}

	bytesToDiscard := 0
	switch buf[3] {
	case socks5IP4:
		bytesToDiscard = net.IPv4len
	case socks5IP6:
		bytesToDiscard = net.IPv6len
	case socks5Domain:
		_, err := io.ReadFull(conn, buf[:1])
		if err != nil {
			return errors.New("proxy: failed to read domain length from SOCKS5 proxy at " + conn.RemoteAddr().String() + ": " + err.Error())
		}
		bytesToDiscard = int(buf[0])
	default:
		return errors.New("proxy: got unknown address type " + strconv.Itoa(int(buf[3])) + " from SOCKS5 proxy at " + conn.RemoteAddr().String())
	}

	if cap(buf) < bytesToDiscard {
		buf = make([]byte, bytesToDiscard)
	} else {
		buf = buf[:bytesToDiscard]
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		return errors.New("proxy: failed to read address from SOCKS5 proxy at " + conn.RemoteAddr().String() + ": " + err.Error())
	}

	// Also need to discard the port number
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return errors.New("proxy: failed to read port from SOCKS5 proxy at " + conn.RemoteAddr().String() + ": " + err.Error())
	}

	return nil
}
