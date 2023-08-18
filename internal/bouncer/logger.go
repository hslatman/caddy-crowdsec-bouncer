package bouncer

import (
	"errors"

	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type zapAdapterHook struct {
	logger         *zap.Logger
	shouldFailHard bool
	address        string
}

func (zh *zapAdapterHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (zh *zapAdapterHook) Fire(entry *logrus.Entry) error {
	if zh == nil || zh.logger == nil {
		return nil
	}

	if entry == nil {
		return nil
	}

	// TODO: extract details from entry.Data? But doesn't seem to be used by CrowdSec today.

	msg := entry.Message
	fields := []zapcore.Field{zap.String("address", zh.address)}
	switch {
	case entry.Level <= logrus.ErrorLevel: // error, fatal, panic
		fields = append(fields, zap.Error(errors.New(msg)))
		if zh.shouldFailHard {
			// TODO: if we keep this Fatal and the "shouldFailhard" around, ensure we
			// shut the bouncer down nicely
			zh.logger.Fatal(msg, fields...)
		} else {
			zh.logger.Error(msg, fields...)
		}
	default:
		level := zapcore.DebugLevel
		if l, ok := levelAdapter[entry.Level]; ok {
			level = l
		}
		zh.logger.Log(level, msg, fields...)
	}

	return nil
}

var levelAdapter = map[logrus.Level]zapcore.Level{
	logrus.TraceLevel: zapcore.DebugLevel, // no trace level in zap
	logrus.DebugLevel: zapcore.DebugLevel,
	logrus.InfoLevel:  zapcore.InfoLevel,
	logrus.WarnLevel:  zapcore.WarnLevel,
	logrus.ErrorLevel: zapcore.ErrorLevel,
	logrus.FatalLevel: zapcore.FatalLevel,
	logrus.PanicLevel: zapcore.PanicLevel,
}

var _ logrus.Hook = (*zapAdapterHook)(nil)
