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
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func newCaddyVarsContext() (ctx context.Context) {
	ctx = context.WithValue(context.Background(), caddyhttp.VarsCtxKey, map[string]any{})
	return
}

func Test_determineIPFromRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/caddy", nil)
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
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    netip.Addr
		wantErr bool
	}{
		{"ok", args{r.WithContext(okCtx)}, netip.MustParseAddr("127.0.0.1"), false},
		{"no-ip", args{r.WithContext(noIPCtx)}, netip.Addr{}, true},
		{"wrong-type", args{r.WithContext(wrongTypeCtx)}, netip.Addr{}, true},
		{"empty-ip", args{r.WithContext(emptyIPCtx)}, netip.Addr{}, true},
		{"invalid-ip", args{r.WithContext(invalidIPCtx)}, netip.Addr{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := determineIPFromRequest(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("determineIPFromRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("determineIPFromRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
