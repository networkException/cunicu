// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package pb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// SignalingClient is the client API for Signaling service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SignalingClient interface {
	Subscribe(ctx context.Context, in *SubscribeParams, opts ...grpc.CallOption) (Signaling_SubscribeClient, error)
	Publish(ctx context.Context, in *SignalingEnvelope, opts ...grpc.CallOption) (*Error, error)
}

type signalingClient struct {
	cc grpc.ClientConnInterface
}

func NewSignalingClient(cc grpc.ClientConnInterface) SignalingClient {
	return &signalingClient{cc}
}

func (c *signalingClient) Subscribe(ctx context.Context, in *SubscribeParams, opts ...grpc.CallOption) (Signaling_SubscribeClient, error) {
	stream, err := c.cc.NewStream(ctx, &Signaling_ServiceDesc.Streams[0], "/wice.Signaling/Subscribe", opts...)
	if err != nil {
		return nil, err
	}
	x := &signalingSubscribeClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Signaling_SubscribeClient interface {
	Recv() (*SignalingEnvelope, error)
	grpc.ClientStream
}

type signalingSubscribeClient struct {
	grpc.ClientStream
}

func (x *signalingSubscribeClient) Recv() (*SignalingEnvelope, error) {
	m := new(SignalingEnvelope)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *signalingClient) Publish(ctx context.Context, in *SignalingEnvelope, opts ...grpc.CallOption) (*Error, error) {
	out := new(Error)
	err := c.cc.Invoke(ctx, "/wice.Signaling/Publish", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SignalingServer is the server API for Signaling service.
// All implementations must embed UnimplementedSignalingServer
// for forward compatibility
type SignalingServer interface {
	Subscribe(*SubscribeParams, Signaling_SubscribeServer) error
	Publish(context.Context, *SignalingEnvelope) (*Error, error)
	mustEmbedUnimplementedSignalingServer()
}

// UnimplementedSignalingServer must be embedded to have forward compatible implementations.
type UnimplementedSignalingServer struct {
}

func (UnimplementedSignalingServer) Subscribe(*SubscribeParams, Signaling_SubscribeServer) error {
	return status.Errorf(codes.Unimplemented, "method Subscribe not implemented")
}
func (UnimplementedSignalingServer) Publish(context.Context, *SignalingEnvelope) (*Error, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Publish not implemented")
}
func (UnimplementedSignalingServer) mustEmbedUnimplementedSignalingServer() {}

// UnsafeSignalingServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SignalingServer will
// result in compilation errors.
type UnsafeSignalingServer interface {
	mustEmbedUnimplementedSignalingServer()
}

func RegisterSignalingServer(s grpc.ServiceRegistrar, srv SignalingServer) {
	s.RegisterService(&Signaling_ServiceDesc, srv)
}

func _Signaling_Subscribe_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(SubscribeParams)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(SignalingServer).Subscribe(m, &signalingSubscribeServer{stream})
}

type Signaling_SubscribeServer interface {
	Send(*SignalingEnvelope) error
	grpc.ServerStream
}

type signalingSubscribeServer struct {
	grpc.ServerStream
}

func (x *signalingSubscribeServer) Send(m *SignalingEnvelope) error {
	return x.ServerStream.SendMsg(m)
}

func _Signaling_Publish_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignalingEnvelope)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SignalingServer).Publish(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/wice.Signaling/Publish",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SignalingServer).Publish(ctx, req.(*SignalingEnvelope))
	}
	return interceptor(ctx, in, info, handler)
}

// Signaling_ServiceDesc is the grpc.ServiceDesc for Signaling service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Signaling_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "wice.Signaling",
	HandlerType: (*SignalingServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Publish",
			Handler:    _Signaling_Publish_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Subscribe",
			Handler:       _Signaling_Subscribe_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "signaling.proto",
}