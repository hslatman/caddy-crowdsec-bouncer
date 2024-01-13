package bouncer

import (
	"errors"
	"io"
	"unicode"
	"unicode/utf8"

	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// overrideLogrusLogger overrides the (default) settings of the standard
// logrus logger. The logrus logger is used by the `go-cs-bouncer` package,
// whereas Caddy uses zap. The output of the standard logger is discarded,
// and a hook is used to send messages to Caddy's zap logger instead.
//
// Note that this method changes global state, but only after a new Bouncer
// is provisioned, validated and has just been started. This should thus
// generally not be a problem.
func (b *Bouncer) overrideLogrusLogger() {
	// the CrowdSec go-cs-bouncer uses the standard logrus logger
	std := logrus.StandardLogger()

	// silence the default CrowdSec logrus logging
	std.SetOutput(io.Discard)

	// replace all hooks on the standard logrus logger
	hooks := logrus.LevelHooks{}
	hooks.Add(&zapAdapterHook{
		logger:         b.logger,
		shouldFailHard: b.shouldFailHard,
		address:        b.streamingBouncer.APIUrl,
		instanceID:     b.instanceID,
	})

	std.ReplaceHooks(hooks)
}

type zapAdapterHook struct {
	logger         *zap.Logger
	shouldFailHard bool
	address        string
	instanceID     string
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
	fields := []zapcore.Field{zap.String("instance_id", zh.instanceID), zap.String("address", zh.address)}
	switch {
	case entry.Level <= logrus.ErrorLevel: // error, fatal, panic
		fields = append(fields, zap.Error(errors.New(msg)))
		if zh.shouldFailHard {
			// TODO: if we keep this Fatal and the "shouldFailhard" around, ensure we
			// shut the bouncer down nicely
			zh.logger.Fatal(firstToLower(msg), fields...)
		} else {
			zh.logger.Error(firstToLower(msg), fields...)
		}
	default:
		level := zapcore.DebugLevel
		if l, ok := levelAdapter[entry.Level]; ok {
			level = l
		}
		zh.logger.Log(level, firstToLower(msg), fields...)
	}

	return nil
}

func firstToLower(s string) string {
	r, size := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError && size <= 1 {
		return s
	}
	lc := unicode.ToLower(r)
	if r == lc {
		return s
	}
	return string(lc) + s[size:]
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
