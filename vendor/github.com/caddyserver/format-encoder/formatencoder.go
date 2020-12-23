// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package formatencoder

import (
	"fmt"
	"strings"

	"github.com/buger/jsonparser"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/logging"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

func init() {
	caddy.RegisterModule(FormattedEncoder{})
}

const commonLogFormat = `{common_log}`

// FormattedEncoder allows the user to provide custom template for log prints. The
// encoder builds atop the json encoder, thus it follows its message structure. The placeholders
// are namespaced by the name of the app logging the message.
type FormattedEncoder struct {
	logging.LogEncoderConfig
	zapcore.Encoder `json:"-"`
	Template        string `json:"template,omitempty"`
	Placeholder     string `json:"placeholder,omitempty"`
}

func (FormattedEncoder) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.logging.encoders.formatted",
		New: func() caddy.Module {
			return &FormattedEncoder{
				Encoder: new(logging.JSONEncoder),
			}
		},
	}
}

// Provision sets up the encoder.
func (se *FormattedEncoder) Provision(ctx caddy.Context) error {
	if se.Template == "" {
		return fmt.Errorf("missing template for formatted log encoder")
	}
	if se.Placeholder == "" {
		se.Placeholder = `-`
	}
	se.Encoder = zapcore.NewJSONEncoder(se.ZapcoreEncoderConfig())
	return nil
}

// Clone wraps the underlying encoder's Clone. This is
// necessary because we implement our own EncodeEntry,
// and if we simply let the embedded encoder's Clone
// be promoted, it would return a clone of that, and
// we'd lose our FormattedEncoder's EncodeEntry.
func (se FormattedEncoder) Clone() zapcore.Encoder {
	return FormattedEncoder{
		Encoder:     se.Encoder.Clone(),
		Template:    se.Template,
		Placeholder: se.Placeholder,
	}
}

// EncodeEntry partially implements the zapcore.Encoder interface.
func (se FormattedEncoder) EncodeEntry(ent zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	repl := caddy.NewReplacer()
	buf, err := se.Encoder.EncodeEntry(ent, fields)
	if err != nil {
		return buf, err
	}
	repl.Map(func(key string) (interface{}, bool) {
		path := strings.Split(key, ">")
		value, dataType, _, err := jsonparser.Get(buf.Bytes(), path...)
		if err != nil {
			return nil, false
		}
		switch dataType {
		case jsonparser.NotExist:
			return nil, false
		case jsonparser.Array, jsonparser.Boolean, jsonparser.Null, jsonparser.Number, jsonparser.Object, jsonparser.String, jsonparser.Unknown:
			// if a value exists, return it as is. A byte is a byte is a byte. The replacer handles them just fine.
			return value, true
		default:
			return nil, false
		}
	})

	out := repl.ReplaceAll(se.Template, se.Placeholder)
	// The buffer is only used to find the values of placeholders.
	// The content has served its purpose. It's time for it to go to repurpose the buffer.
	buf.Reset()

	// Unescape escaped quotes
	buf.AppendString(strings.Replace(out, `\"`, `"`, -1))
	if !strings.HasSuffix(out, "\n") {
		buf.AppendByte('\n')
	}
	return buf, err
}
