package core

import "strings"

type PeerModifier uint32

const (
	PeerModifiedNone         PeerModifier = 0
	PeerModifiedPresharedKey PeerModifier = (1 << iota)
	PeerModifiedEndpoint
	PeerModifiedKeepaliveInterval
	PeerModifiedHandshakeTime
	PeerModifiedReceiveBytes
	PeerModifiedTransmitBytes
	PeerModifiedAllowedIPs
	PeerModifiedProtocolVersion
	PeerModifiedName
	PeerModifierCount = iota
)

var (
	peerModifiersStrings = []string{
		"preshared-key",
		"endpoint",
		"keepalive-interval",
		"handshake-time",
		"receive-bytes",
		"transmit-bytes",
		"allowed-ips",
		"protocol-version",
		"name",
	}
)

func (i PeerModifier) Strings() []string {
	modifiers := []string{}

	for j := 0; j <= PeerModifierCount; j++ {
		if i&(1<<j) != 0 {
			modifiers = append(modifiers, peerModifiersStrings[j])
		}
	}

	return modifiers
}

func (i PeerModifier) String() string {
	return strings.Join(i.Strings(), ",")
}

func (i PeerModifier) Is(j PeerModifier) bool {
	return i&j > 0
}
