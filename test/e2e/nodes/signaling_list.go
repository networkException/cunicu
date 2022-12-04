//nolint:dupl
package nodes

import (
	"fmt"

	g "github.com/stv0g/gont/pkg"
)

type SignalingList []SignalingNode

func AddSignalingNodes(n *g.Network, numNodes int, opts ...g.Option) (SignalingList, error) {
	ns := SignalingList{}

	for i := 1; i <= numNodes; i++ {
		n, err := NewGrpcSignalingNode(n, fmt.Sprintf("n%d", i))
		if err != nil {
			return nil, fmt.Errorf("failed to create signaling node: %w", err)
		}

		ns = append(ns, n)
	}

	return ns, nil
}

func (l SignalingList) Start(dir string, extraArgs ...any) error {
	for _, n := range l {
		if err := n.Start("", dir, extraArgs...); err != nil {
			return err
		}
	}

	return nil
}

func (l SignalingList) Close() error {
	for _, n := range l {
		if err := n.Close(); err != nil {
			return err
		}
	}

	return nil
}
