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
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
)

func TestEnsureIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/caddy", http.NoBody)
	ipFromRequest := newCaddyVarsContext()
	caddyhttp.SetVar(ipFromRequest, caddyhttp.ClientIPVarKey, "127.0.0.1")
	ipFromContext := newCaddyVarsContext()
	caddyhttp.SetVar(ipFromContext, caddyhttp.ClientIPVarKey, "127.0.0.2")
	ipFromContext = newContext(ipFromContext, netip.MustParseAddr("127.0.0.3"))
	invalidIPCtx := newCaddyVarsContext()
	caddyhttp.SetVar(invalidIPCtx, caddyhttp.ClientIPVarKey, "127.0.0.1.x")

	type args struct {
		ctx context.Context
		r   *http.Request
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
				r:   r.WithContext(ipFromRequest),
				ctx: ipFromRequest,
			},
			wantIP: netip.MustParseAddr("127.0.0.1"),
		},
		{
			name: "ip-from-context",
			args: args{
				r:   r.WithContext(ipFromContext),
				ctx: ipFromContext,
			},
			wantIP: netip.MustParseAddr("127.0.0.3"),
		},
		{
			name: "invalid-ip",
			args: args{
				r:   r.WithContext(invalidIPCtx),
				ctx: invalidIPCtx,
			},
			wantIP: netip.Addr{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, ip := EnsureIP(tt.args.ctx, tt.args.r)

			assert.Equal(t, tt.wantIP, ip)
			assert.Equal(t, tt.wantIP, ctx.Value(contextKey{}).(netip.Addr))
		})
	}
}
