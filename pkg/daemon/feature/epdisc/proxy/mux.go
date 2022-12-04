package proxy

import (
	"errors"
	"net"

	"github.com/pion/ice/v2"
	"github.com/stv0g/cunicu/pkg/log"
	"go.uber.org/zap"
)

var errInvalidCast = errors.New("invalid cast")

func CreateUDPMux() (ice.UDPMux, int, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, 0, err
	}

	lAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, -1, errInvalidCast
	}

	mux := ice.NewUDPMuxDefault(ice.UDPMuxParams{
		UDPConn: conn,
		Logger:  log.NewPionLoggerFactory(zap.L()).NewLogger("udpmux"),
	})

	return mux, lAddr.Port, nil
}

func CreateUniversalUDPMux() (ice.UniversalUDPMux, int, error) {
	// We do not need a filtered connection here as we anyway need to redirect
	// the non-STUN traffic via nftables

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, 0, err
	}

	lAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, -1, errInvalidCast
	}

	mux := ice.NewUniversalUDPMuxDefault(ice.UniversalUDPMuxParams{
		UDPConn: conn,
		Logger:  log.NewPionLoggerFactory(zap.L()).NewLogger("udpmux-universal"),
	})

	return mux, lAddr.Port, nil
}
