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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnsureIP(t *testing.T) {
	ipFromRequest := newCaddyVarsContext()
	caddyhttp.SetVar(ipFromRequest, caddyhttp.ClientIPVarKey, "127.0.0.1")
	ipFromContext := newCaddyVarsContext()
	caddyhttp.SetVar(ipFromContext, caddyhttp.ClientIPVarKey, "127.0.0.2")
	ipFromContext = newContext(ipFromContext, netip.MustParseAddr("127.0.0.3"))
	invalidIPCtx := newCaddyVarsContext()
	caddyhttp.SetVar(invalidIPCtx, caddyhttp.ClientIPVarKey, "127.0.0.1.x")

	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		args    args
		wantCtx context.Context
		wantIP  netip.Addr
	}{
		{
			name: "ip-from-request",
			args: args{
				ctx: ipFromRequest,
			},
			wantIP: netip.MustParseAddr("127.0.0.1"),
		},
		{
			name: "ip-from-context",
			args: args{
				ctx: ipFromContext,
			},
			wantIP: netip.MustParseAddr("127.0.0.3"),
		},
		{
			name: "invalid-ip",
			args: args{
				ctx: invalidIPCtx,
			},
			wantIP: netip.Addr{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, ip := EnsureIP(tt.args.ctx)

			assert.Equal(t, tt.wantIP, ip)
			assert.Equal(t, tt.wantIP, ctx.Value(contextKey{}).(netip.Addr))
		})
	}
}

func TestFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextKey{}, nil)
	got, ok := FromContext(ctx)
	require.False(t, ok)
	require.Equal(t, netip.Addr{}, got)
	require.False(t, got.IsValid())

	ctx = context.WithValue(context.Background(), contextKey{}, netip.Addr{})
	got, ok = FromContext(ctx)
	require.False(t, ok)
	require.Equal(t, netip.Addr{}, got)
	require.False(t, got.IsValid())

	ip := netip.MustParseAddr("127.0.0.1")
	ctx = context.WithValue(context.Background(), contextKey{}, ip)
	got, ok = FromContext(ctx)
	require.True(t, ok)
	require.Equal(t, ip, got)
}
