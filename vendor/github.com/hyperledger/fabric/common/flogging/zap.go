/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package flogging

import (
	"fmt"
	fabric_logs "github.com/hyperledger/fabric/logs"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zapgrpc"
	"strings"
)

// NewZapLogger creates a zap logger around a new zap.Core. The core will use
// the provided encoder and sinks and a level enabler that is associated with
// the provided logger name. The logger that is returned will be named the same
// as the logger.
func NewZapLogger(core zapcore.Core, options ...zap.Option) *zap.Logger {
	return zap.New(
		core,
		append([]zap.Option{
			zap.AddCaller(),
			zap.AddStacktrace(zapcore.ErrorLevel),
		}, options...)...,
	)
}

// NewGRPCLogger creates a grpc.Logger that delegates to a zap.Logger.
func NewGRPCLogger(l *zap.Logger) *zapgrpc.Logger {
	l = l.WithOptions(
		zap.AddCaller(),
		zap.AddCallerSkip(3),
	)
	return zapgrpc.NewLogger(l, zapgrpc.WithDebug())
}

// NewFabricLogger creates a logger that delegates to the zap.SugaredLogger.
func NewFabricLogger(l *zap.Logger, options ...zap.Option) *FabricLogger {
	return &FabricLogger{
		s: l.WithOptions(append(options, zap.AddCallerSkip(1))...).Sugar(),
	}
}

// A FabricLogger is an adapter around a zap.SugaredLogger that provides
// structured logging capabilities while preserving much of the legacy logging
// behavior.
//
// The most significant difference between the FabricLogger and the
// zap.SugaredLogger is that methods without a formatting suffix (f or w) build
// the log entry message with fmt.Sprintln instead of fmt.Sprint. Without this
// change, arguments are not separated by spaces.
type FabricLogger struct{ s *zap.SugaredLogger }

// 【日志转储】 此处执行 日志打印的行号正确
func (f *FabricLogger) DPanic(args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Alert(args...)
	} else {
		f.s.DPanicf(formatArgs(args))
	}
}
func (f *FabricLogger) DPanicf(template string, args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Alertf(template, args...)
	} else {
		f.s.DPanicf(template, args...)
	}
}
func (f *FabricLogger) DPanicw(msg string, kvPairs ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Alertf(msg, nil)
	} else {
		f.s.DPanicw(msg, kvPairs...)
	}
}
func (f *FabricLogger) Debug(args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Debug(args...)
	} else {
		f.s.Debugf(formatArgs(args))
	}
}
func (f *FabricLogger) Debugf(template string, args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Debugf(template, args...)
	} else {
		f.s.Debugf(template, args...)
	}
}
func (f *FabricLogger) Debugw(msg string, kvPairs ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Debugf(msg, nil)
	} else {
		f.s.Debugw(msg, kvPairs...)
	}
}
func (f *FabricLogger) Error(args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Error(args...)
	} else {
		f.s.Errorf(formatArgs(args))
	}
}
func (f *FabricLogger) Errorf(template string, args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Errorf(template, args...)
	} else {
		f.s.Errorf(template, args...)
	}
}
func (f *FabricLogger) Errorw(msg string, kvPairs ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Errorf(msg, nil)
	} else {
		f.s.Errorw(msg, kvPairs...)
	}
}
func (f *FabricLogger) Fatal(args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Emergency(args...)
	} else {
		f.s.Fatalf(formatArgs(args))
	}
}
func (f *FabricLogger) Fatalf(template string, args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Emergencyf(template, args...)
	} else {
		f.s.Fatalf(template, args...)
	}
}
func (f *FabricLogger) Fatalw(msg string, kvPairs ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Emergencyf(msg, nil)
	} else {
		f.s.Fatalw(msg, kvPairs...)
	}
}
func (f *FabricLogger) Info(args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Info(args...)
	} else {
		f.s.Infof(formatArgs(args))
	}
}
func (f *FabricLogger) Infof(template string, args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Infof(template, args...)
	} else {
		f.s.Infof(template, args...)
	}
}
func (f *FabricLogger) Infow(msg string, kvPairs ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Infof(msg, nil)
	} else {
		f.s.Infow(msg, kvPairs...)
	}
}
func (f *FabricLogger) Panic(args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Alert(args...)
	} else {
		f.s.Panicf(formatArgs(args))
	}
}
func (f *FabricLogger) Panicf(template string, args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Alertf(template, args...)
	} else {
		f.s.Panicf(template, args...)
	}
}
func (f *FabricLogger) Panicw(msg string, kvPairs ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Alertf(msg, nil)
	} else {
		f.s.Panicw(msg, kvPairs...)
	}
}
func (f *FabricLogger) Warn(args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Warning(args...)
	} else {
		f.s.Warnf(formatArgs(args))
	}
}
func (f *FabricLogger) Warnf(template string, args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Warningf(template, args...)
	} else {
		f.s.Warnf(template, args...)
	}
}
func (f *FabricLogger) Warnw(msg string, kvPairs ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Warningf(msg, nil)
	} else {
		f.s.Warnw(msg, kvPairs...)
	}
}
func (f *FabricLogger) Warning(args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Warning(args...)
	} else {
		f.s.Warnf(formatArgs(args))
	}
}
func (f *FabricLogger) Warningf(template string, args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Warningf(template, args...)
	} else {
		f.s.Warnf(template, args...)
	}
}

// for backwards compatibility
func (f *FabricLogger) Critical(args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Critical(args...)
	} else {
		f.s.Errorf(formatArgs(args))
	}
}
func (f *FabricLogger) Criticalf(template string, args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Criticalf(template, args...)
	} else {
		f.s.Errorf(template, args...)
	}
}
func (f *FabricLogger) Notice(args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Notice(args...)
	} else {
		f.s.Infof(formatArgs(args))
	}
}
func (f *FabricLogger) Noticef(template string, args ...interface{}) {
	if fabric_logs.GetFabricLogger() != nil {
		fabric_logs.GetFabricLogger().Noticef(template, args...)
	} else {
		f.s.Infof(template, args...)
	}
}

func (f *FabricLogger) Named(name string) *FabricLogger { return &FabricLogger{s: f.s.Named(name)} }
func (f *FabricLogger) Sync() error                     { return f.s.Sync() }
func (f *FabricLogger) Zap() *zap.Logger                { return f.s.Desugar() }

func (f *FabricLogger) IsEnabledFor(level zapcore.Level) bool {
	return f.s.Desugar().Core().Enabled(level)
}

func (f *FabricLogger) With(args ...interface{}) *FabricLogger {
	return &FabricLogger{s: f.s.With(args...)}
}

func (f *FabricLogger) WithOptions(opts ...zap.Option) *FabricLogger {
	l := f.s.Desugar().WithOptions(opts...)
	return &FabricLogger{s: l.Sugar()}
}

func formatArgs(args []interface{}) string { return strings.TrimSuffix(fmt.Sprintln(args...), "\n") }
