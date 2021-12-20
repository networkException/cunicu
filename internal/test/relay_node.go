//go:build linux
// +build linux

package test

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"time"

	"github.com/pion/ice/v2"
	g "github.com/stv0g/gont/pkg"
)

const (
	stunPort = 3478
)

type Relay struct {
	*g.Host

	Command *exec.Cmd

	Config   map[string]string
	Username string
	Password string
}

func NewRelay(n *g.Network, name string) (*Relay, error) {
	h, err := n.AddHost(name)
	if err != nil {
		return nil, err
	}

	t := &Relay{
		Host:     h,
		Username: "user1",
		Password: "password1",
		Config: map[string]string{
			"verbose":        "",
			"lt-cred-mech":   "",
			"log-file":       "/dev/null",
			"listening-port": strconv.Itoa(stunPort),
		},
	}

	t.Config["user"] = fmt.Sprintf("%s:%s", t.Username, t.Password)

	return t, nil
}

func (t *Relay) Start() error {
	var stdout, stderr io.Reader
	var err error
	var args = []interface{}{
		"-n",
	}

	for key, value := range t.Config {
		opt := fmt.Sprintf("--%s", key)
		if value != "" {
			opt += fmt.Sprintf("=%s", value)
		}

		args = append(args, opt)
	}

	if stdout, stderr, t.Command, err = t.Host.Start("turnserver", args...); err != nil {
		return fmt.Errorf("failed to start turnserver: %w", err)
	}

	if _, err = FileWriter("logs/turnserver.log", stdout, stderr); err != nil {
		return fmt.Errorf("failed to create logfile: %w", err)
	}

	return t.WaitReady()
}

func (t *Relay) Stop() error {
	if t.Command == nil || t.Command.Process == nil {
		return nil
	}

	return t.Command.Process.Kill()
}

func (t *Relay) Close() error {
	return t.Stop()
}

func (t *Relay) IsReachable() bool {
	hostPort := fmt.Sprintf("[%s]:%d", net.IPv6loopback, stunPort)

	return t.RunFunc(func() error {
		conn, err := net.Dial("tcp6", hostPort)
		if err != nil {
			return err
		}

		return conn.Close()
	}) == nil
}

func (t *Relay) WaitReady() error {
	for tries := 10; !t.IsReachable(); tries-- {
		if tries == 0 {
			return fmt.Errorf("timed out")
		}

		time.Sleep(100 * time.Millisecond)
	}

	return nil
}

func (t *Relay) URLs() []*ice.URL {
	host := t.Name()

	return []*ice.URL{
		{
			Scheme: ice.SchemeTypeSTUN,
			Host:   host,
			Port:   stunPort,
		},
		{
			Scheme: ice.SchemeTypeTURN,
			Host:   host,
			Port:   stunPort,
			Proto:  ice.ProtoTypeTCP,
		},
		{
			Scheme: ice.SchemeTypeTURN,
			Host:   host,
			Port:   stunPort,
			Proto:  ice.ProtoTypeUDP,
		},
	}
}
