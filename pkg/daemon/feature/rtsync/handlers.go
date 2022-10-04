package rtsync

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/stv0g/cunicu/pkg/core"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (rs *Interface) OnPeerAdded(p *core.Peer) {
	pk := p.PublicKey()

	for _, q := range rs.Settings.AutoConfig.Prefixes {
		gwn := pk.IPAddress(q)
		gw, ok := netip.AddrFromSlice(gwn.IP)
		if !ok {
			panic(fmt.Errorf("failed to get address from slice: %s", gwn))
		}

		rs.gwMap[gw] = p
	}

	rs.syncKernel() // Initial sync

	p.OnModified(rs)
}

func (rs *Interface) OnPeerRemoved(p *core.Peer) {
	pk := p.PublicKey()

	for _, q := range rs.Settings.AutoConfig.Prefixes {
		gwn := pk.IPAddress(q)
		gw, ok := netip.AddrFromSlice(gwn.IP)
		if !ok {
			panic(fmt.Errorf("failed to get address from slice: %s", gwn))
		}

		delete(rs.gwMap, gw)
	}

	if err := rs.removeKernel(p); err != nil {
		rs.logger.Error("Failed to remove kernel routes for peer",
			zap.Error(err),
			zap.Any("intf", p.Interface),
			zap.Any("peer", p),
		)
	}
}

func (rs *Interface) OnPeerModified(p *core.Peer, old *wgtypes.Peer, m core.PeerModifier, ipsAdded, ipsRemoved []net.IPNet) {
	pk := p.PublicKey()

	// Determine peer gateway address by using the first IPv4 and IPv6 prefix
	var gwV4, gwV6 net.IP
	for _, q := range rs.Settings.AutoConfig.Prefixes {
		isV6 := q.IP.To4() == nil
		n := pk.IPAddress(q)
		if isV6 && gwV6 == nil {
			gwV6 = n.IP
		}

		if !isV6 && gwV4 == nil {
			gwV4 = n.IP
		}
	}

	for _, dst := range ipsAdded {
		var gw net.IP
		if isV6 := dst.IP.To4() == nil; isV6 {
			gw = gwV6
		} else {
			gw = gwV4
		}

		ones, bits := dst.Mask.Size()
		if gw != nil && ones == bits && dst.IP.Equal(gw) {
			gw = nil
		}

		if err := p.Interface.KernelDevice.AddRoute(dst, gw, rs.Settings.RouteSync.Table); err != nil {
			rs.logger.Error("Failed to add route", zap.Error(err))
			continue
		}

		rs.logger.Info("Added new AllowedIP to kernel routing table",
			zap.String("dst", dst.String()),
			zap.Any("gw", gw.String()),
			zap.Any("intf", p.Interface),
			zap.Any("peer", p))
	}

	for _, dst := range ipsRemoved {
		if err := p.Interface.KernelDevice.DeleteRoute(dst, rs.Settings.RouteSync.Table); err != nil && !errors.Is(err, syscall.ESRCH) {
			rs.logger.Error("Failed to delete route", zap.Error(err))
			continue
		}

		rs.logger.Info("Remove vanished AllowedIP from kernel routing table",
			zap.String("dst", dst.String()),
			zap.Any("intf", p.Interface),
			zap.Any("peer", p))
	}
}