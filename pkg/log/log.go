// Package log implements adapters between logging types of various used packages
package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc/grpclog"
	"k8s.io/klog/v2"
)

func SetupLogging(level zapcore.Level, outputPaths []string, errOutputPaths []string, color bool) *zap.Logger {
	cfg := zap.NewDevelopmentConfig()

	cfg.Level = zap.NewAtomicLevelAt(level)
	cfg.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05.009")
	if color {
		cfg.EncoderConfig.EncodeLevel = zapcore.LowercaseColorLevelEncoder
	} else {
		cfg.EncoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
	}
	cfg.DisableCaller = true
	cfg.DisableStacktrace = true
	cfg.OutputPaths = outputPaths
	cfg.ErrorOutputPaths = errOutputPaths

	if len(cfg.OutputPaths) == 0 {
		cfg.OutputPaths = []string{"stdout"}
	}

	if len(cfg.ErrorOutputPaths) == 0 {
		cfg.ErrorOutputPaths = []string{"stderr"}
	}

	logger, err := cfg.Build()
	if err != nil {
		panic(err)
	}

	// Redirect Kubernetes log to Zap
	klogger := logger.Named("backend.k8s")
	klog.SetLogger(NewK8SLogger(klogger))

	// Redirect gRPC log to Zap
	glogger := logger.Named("grpc")
	grpclog.SetLoggerV2(NewGRPCLogger(glogger))

	zap.RedirectStdLog(logger)
	zap.ReplaceGlobals(logger)

	return logger
}

// WithLevel sets the loggers leveler to the one given.
func WithLevel(level zapcore.LevelEnabler) zap.Option {
	return zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		return &lvlCore{
			Core: core,
			l:    level,
		}
	})
}

type lvlCore struct {
	zapcore.Core
	l zapcore.LevelEnabler
}

func (c *lvlCore) Enabled(lvl zapcore.Level) bool {
	return c.l.Enabled(lvl)
}

func (c *lvlCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.l.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}

	return ce
}
