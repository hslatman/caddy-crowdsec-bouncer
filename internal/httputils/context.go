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
	"net/netip"
)

type contextKey struct{}

func EnsureIP(ctx context.Context, r *http.Request) (context.Context, netip.Addr) { // TODO: pass in ctx only?
	var (
		ip  netip.Addr
		err error
	)

	ip, ok := FromContext(ctx)
	if !ok {
		if ip, err = determineIPFromRequest(r); err != nil { // TODO: pass in ctx only?
			ip = netip.Addr{}
		}

		ctx = newContext(ctx, ip)
	}

	return ctx, ip
}

func newContext(ctx context.Context, ip netip.Addr) context.Context {
	return context.WithValue(ctx, contextKey{}, ip)
}

func FromContext(ctx context.Context) (netip.Addr, bool) {
	v, ok := ctx.Value(contextKey{}).(netip.Addr)
	if !ok {
		return netip.Addr{}, false
	}

	if !v.IsValid() {
		return v, false
	}

	return v, true
}
