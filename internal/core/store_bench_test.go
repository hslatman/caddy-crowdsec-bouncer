// Copyright 2021 Herman Slatman
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

package core

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

func BenchmarkStoreLookupByDecisionCount(b *testing.B) {
	for _, decisionCount := range []int{1_000, 10_000, 100_000} {
		decisionCount := decisionCount
		b.Run(fmt.Sprintf("decisions_%d", decisionCount), func(b *testing.B) {
			store := benchmarkStore(b, decisionCount)
			hit := benchmarkIPv4(decisionCount - 1)
			miss := netip.MustParseAddr("203.0.113.1")

			b.Run("hit", func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					decision, err := store.get(hit)
					if err != nil {
						b.Fatal(err)
					}
					if decision == nil {
						b.Fatal("expected a matching decision")
					}
				}
			})

			b.Run("miss", func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					decision, err := store.get(miss)
					if err != nil {
						b.Fatal(err)
					}
					if decision != nil {
						b.Fatal("expected no matching decision")
					}
				}
			})
		})
	}
}

func BenchmarkStoreLookupParallel100K(b *testing.B) {
	store := benchmarkStore(b, 100_000)
	hit := benchmarkIPv4(99_999)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			decision, err := store.get(hit)
			if err != nil {
				b.Error(err)
				return
			}
			if decision == nil {
				b.Error("expected a matching decision")
				return
			}
		}
	})
}

func benchmarkStore(b *testing.B, decisionCount int) *store {
	b.Helper()
	b.StopTimer()

	result := newStore()
	for index := range decisionCount {
		if err := result.add(benchmarkDecision(int64(index+1), benchmarkIPv4(index))); err != nil {
			b.Fatal(err)
		}
	}

	b.StartTimer()
	return result
}

func benchmarkDecision(id int64, address netip.Addr) *models.Decision {
	duration := "1h"
	scope := "Ip"
	typ := "ban"
	value := address.String()

	return &models.Decision{
		Duration: &duration,
		ID:       id,
		Scope:    &scope,
		Type:     &typ,
		Value:    &value,
	}
}

func benchmarkIPv4(index int) netip.Addr {
	value := uint32(index)
	return netip.AddrFrom4([4]byte{
		10,
		byte(value >> 16),
		byte(value >> 8),
		byte(value),
	})
}
