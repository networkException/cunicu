//go:build linux

package test_test

import (
	"context"
	"fmt"
	"time"

	"riasc.eu/wice/pkg/crypto"
	"riasc.eu/wice/pkg/util"
	"riasc.eu/wice/pkg/wg"
	"riasc.eu/wice/test/nodes"
	wopt "riasc.eu/wice/test/nodes/options/wg"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	g "github.com/stv0g/gont/pkg"
	gopt "github.com/stv0g/gont/pkg/options"
)

/* Simple local-area switched topology with 2 agents
 *
 *  - 1x Signaling node    [s1] (GRPC server)
 *  - 1x Switch            [sw1]
 *  - 2x  wice Agent nodes [n?]
 *
 *         Signaling
 *          ┌─────┐
 *          │  s1 │
 *          └──┬──┘
 *             │
 *          ┌──┴──┐
 *          │ sw1 │ Switch
 *          └┬───┬┘
 *       ┌───┘   └───┐
 *    ┌──┴─┐       ┌─┴──┐
 *    │ n1 │       │ n2 │
 *    └────┘       └────┘
 *         wice Agents
 */
var _ = Context("restart", func() {
	var (
		err error
		n   Network
		nw  *g.Network

		s1     *nodes.GrpcSignalingNode
		n1, n2 *nodes.Agent
	)

	BeforeEach(OncePerOrdered, func() {
		n.Init()

		n.AgentOptions = append(n.AgentOptions,
			gopt.EmptyDir(wg.ConfigPath),
			gopt.EmptyDir(wg.SocketPath),
		)

		n.WireGuardInterfaceOptions = append(n.WireGuardInterfaceOptions,
			wopt.FullMeshPeers,
		)
	})

	AfterEach(OncePerOrdered, func() {
		n.Close()
	})

	JustBeforeEach(OncePerOrdered, func() {
		By("Initializing core network")

		nw, err = g.NewNetwork(n.Name, n.NetworkOptions...)
		Expect(err).To(Succeed(), "Failed to create network: %s", err)

		sw1, err := nw.AddSwitch("sw1")
		Expect(err).To(Succeed(), "Failed to create switch: %s", err)

		By("Initializing signaling node")

		s1, err = nodes.NewGrpcSignalingNode(nw, "s1",
			gopt.Interface("eth0", sw1,
				gopt.AddressIP("10.0.0.2/16"),
				gopt.AddressIP("fc::2/64"),
			),
		)
		Expect(err).To(Succeed(), "Failed to create signaling node: %s", err)

		By("Initializing agent nodes")

		AddAgent := func(i int) *nodes.Agent {
			a, err := nodes.NewAgent(nw, fmt.Sprintf("n%d", i),
				gopt.Customize(n.AgentOptions,
					gopt.Interface("eth0", sw1,
						gopt.AddressIP("10.0.1.%d/16", i),
						gopt.AddressIP("fc::1:%d/64", i),
					),
					wopt.Interface("wg0",
						gopt.Customize(n.WireGuardInterfaceOptions,
							wopt.AddressIP("172.16.0.%d/16", i),
						)...,
					),
				)...,
			)
			Expect(err).To(Succeed(), "Failed to create agent node: %s", err)

			n.AgentNodes = append(n.AgentNodes, a)

			return a
		}

		n1 = AddAgent(1)
		n2 = AddAgent(2)

		By("Starting network")

		n.Network = nw
		n.SignalingNodes = nodes.SignalingList{s1}

		n.Start()
	})

	RestartTest := func(restart func(gap time.Duration)) {
		var gap time.Duration

		ConnectivityTestCycle := func() {
			n.ConnectivityTests()

			It("", func() {
				By("Triggering restart")

				restart(gap)

				time.Sleep(gap)
			})

			n.ConnectivityTests()
		}

		Context("quick", Ordered, func() {
			BeforeEach(func() {
				gap = 3 * time.Second
			})

			ConnectivityTestCycle()
		})

		Context("slow", Ordered, func() {
			BeforeEach(func() {
				gap = 10 * time.Second // > ICE failed/disconnected timeout (5s)
			})

			ConnectivityTestCycle()
		})
	}

	Context("agent", func() {
		RestartTest(func(gap time.Duration) {
			By("Stopping first agent")

			err = n1.Stop()
			Expect(err).To(Succeed(), "Failed to stop first agent: %s", err)

			By("Waiting some time")

			time.Sleep(gap)

			By("Re-starting first agent again")

			err = n1.Start("", n.BasePath, n.AgentArgs()...)
			Expect(err).To(Succeed(), "Failed to restart first agent: %s", err)
		})
	})

	Context("addresses", Pending, func() {
		RestartTest(func(gap time.Duration) {
			i := n1.Interface("eth0")
			Expect(i).NotTo(BeNil(), "Failed to find agent interface")

			By("Deleting old addresses from agent interface")

			for _, a := range i.Addresses {
				err = i.DeleteAddress(&a)
				Expect(err).To(Succeed(), "Failed to remove IP address '%s': %s", a.String(), err)
			}

			By("Waiting some time")

			time.Sleep(gap)

			By("Assigning new addresses to agent interface")

			for _, a := range i.Addresses {
				ao := a
				ao.IP = util.OffsetIP(ao.IP, 128)

				err = i.AddAddress(&ao)
				Expect(err).To(Succeed(), "Failed to add IP address '%s': %s", a.String(), err)
			}

			out, _, _ := n1.Run("ip", "a")
			GinkgoWriter.Write(out)

			out, _, _ = n1.Run("wg")
			GinkgoWriter.Write(out)

			out, _, _ = n2.Run("wg")
			GinkgoWriter.Write(out)
		})
	})

	Context("link", Pending, func() {
		RestartTest(func(gap time.Duration) {
			i := n1.Interface("eth0")
			Expect(i).NotTo(BeNil(), "Failed to find agent interface")

			By("Bringing interface of first agent down")

			err = i.SetDown()
			Expect(err).To(Succeed(), "Failed to bring interface down: %s", err)

			By("Waiting some time")

			time.Sleep(gap)

			By("Bringing interface of first agent back up")

			err = i.SetUp()
			Expect(err).To(Succeed(), "Failed to bring interface back up: %s", err)
		})
	})

	Context("rpc", func() {
		RestartTest(func(gap time.Duration) {
			ctx := context.Background()

			i := n1.WireGuardInterfaces[0]
			p := i.Peers[0]
			pk := (*crypto.Key)(&p.PublicKey)

			By("Initiating restart via RPC")

			err = n1.Client.RestartPeer(ctx, i.Name, pk)
			Expect(err).To(Succeed(), "Failed to restart peer: %s", err)
		})
	})

	Context("signaling", Pending, func() {
		RestartTest(func(gap time.Duration) {
			By("Stopping signaling server")

			err = s1.Stop()
			Expect(err).To(Succeed(), "Failed to stop signaling server")

			By("Waiting some time")

			time.Sleep(gap)

			By("Re-starting signaling server again")

			err = s1.Start("", n.BasePath)
			Expect(err).To(Succeed(), "Failed to restart signaling server: %s", err)
		})
	})
})