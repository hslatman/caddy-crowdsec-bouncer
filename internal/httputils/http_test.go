// Copyright 2024 Herman Slatman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httputils

import (
	"context"
	"net/netip"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

func newCaddyVarsContext() (ctx context.Context) {
	ctx = context.WithValue(context.Background(), caddyhttp.VarsCtxKey, map[string]any{})
	return
}

func Test_determineIPFromRequest(t *testing.T) {
	okCtx := newCaddyVarsContext()
	caddyhttp.SetVar(okCtx, caddyhttp.ClientIPVarKey, "127.0.0.1")
	noIPCtx := newCaddyVarsContext()
	wrongTypeCtx := newCaddyVarsContext()
	caddyhttp.SetVar(wrongTypeCtx, caddyhttp.ClientIPVarKey, 42)
	emptyIPCtx := newCaddyVarsContext()
	caddyhttp.SetVar(emptyIPCtx, caddyhttp.ClientIPVarKey, "")
	invalidIPCtx := newCaddyVarsContext()
	caddyhttp.SetVar(invalidIPCtx, caddyhttp.ClientIPVarKey, "127.0.0.1.x")
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		args    args
		want    netip.Addr
		wantErr bool
	}{
		{"ok", args{okCtx}, netip.MustParseAddr("127.0.0.1"), false},
		{"no-ip", args{noIPCtx}, netip.Addr{}, true},
		{"wrong-type", args{wrongTypeCtx}, netip.Addr{}, true},
		{"empty-ip", args{emptyIPCtx}, netip.Addr{}, true},
		{"invalid-ip", args{invalidIPCtx}, netip.Addr{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := determineIPFromRequest(tt.args.ctx)
			if tt.wantErr {
				require.Error(t, err)
				require.Equal(t, netip.Addr{}, got)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
