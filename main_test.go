package main

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	nats "github.com/nats-io/go-nats"
)

func TestSSLping(t *testing.T) {
	var nc *nats.Conn
	nc, _ = nats.Connect("nats://localhost:4222")

	req := request{
		Hostname: "sslping.com",
		Host:     "195.154.227.44",
		Port:     443,
	}
	bytes, _ := json.Marshal(req)
	msg, err := nc.Request("vuln.HEARTBLEED.US", bytes, time.Second*100)
	if err != nil {
		fmt.Println(err)
	}
	res := response{}
	json.Unmarshal(msg.Data, &res)

	if res.Host != req.Host {
		t.Fatal("Host changed")
	}
	if res.Port != req.Port {
		t.Fatal("Port changed")
	}
	if res.Hostname != req.Hostname {
		t.Fatal("Hostname changed")
	}
	if res.Error != "" {
		t.Fatal("Error not nil", res.Error)
	}
	if res.Vulnerable {
		t.Fatal("SSLping shouldn't be vulnerable")
	}
}

func TestVulnerable(t *testing.T) {
	var nc *nats.Conn
	nc, _ = nats.Connect("nats://localhost:4222")
	fmt.Print("Connected to NATS")

	req := request{
		Hostname: "exjtools.com",
		Host:     "61.195.156.135",
		Port:     443,
	}
	bytes, _ := json.Marshal(req)
	msg, err := nc.Request("vuln.HEARTBLEED.US", bytes, time.Second*100)
	if err != nil {
		fmt.Println(err)
	}
	res := response{}
	json.Unmarshal(msg.Data, &res)

	if res.Host != req.Host {
		t.Fatal("Host changed")
	}
	if res.Port != req.Port {
		t.Fatal("Port changed")
	}
	if res.Hostname != req.Hostname {
		t.Fatal("Hostname changed")
	}
	if res.Error != "" {
		t.Fatal("Error not nil")
	}
	if !res.Vulnerable {
		t.Fatal("twr1.thewaiting-room.net should be vulnerable")
	}
}

func TestTimeout(t *testing.T) {
	var nc *nats.Conn
	nc, _ = nats.Connect("nats://localhost:4222")
	fmt.Print("Connected to NATS")

	req := request{
		Hostname: "it.will.not.work",
		Host:     "192.168.44.55",
		Port:     443,
	}
	bytes, _ := json.Marshal(req)
	msg, err := nc.Request("vuln.HEARTBLEED.US", bytes, time.Second*100)
	if err != nil {
		fmt.Println(err)
	}
	res := response{}
	json.Unmarshal(msg.Data, &res)

	if res.Host != req.Host {
		t.Fatal("Host changed")
	}
	if res.Port != req.Port {
		t.Fatal("Port changed")
	}
	if res.Hostname != req.Hostname {
		t.Fatal("Hostname changed")
	}
	if res.Error == "" {
		t.Fatal("Error should not be nil")
	}
}
