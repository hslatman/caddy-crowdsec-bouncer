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

package bouncer

import (
	"net"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestStore(t *testing.T) {
	duration := "120s"
	source := "cscli"
	scenario := "manual ban ..."
	scopeIP := "Ip"
	scopeRange := "Range"
	typ := "ban"
	value1 := "127.0.0.1"
	value2 := "127.0.0.2"
	value3 := "10.0.0.1/24"
	value4 := "128.0.0.1/32"
	value5 := "129.0.0.1/24"

	d1 := &models.Decision{
		Duration: &duration,
		ID:       1,
		Origin:   &source,
		Scenario: &scenario,
		Scope:    &scopeIP,
		Type:     &typ,
		Value:    &value1,
	}

	d2 := &models.Decision{
		Duration: &duration,
		ID:       2,
		Origin:   &source,
		Scenario: &scenario,
		Scope:    &scopeIP,
		Type:     &typ,
		Value:    &value2,
	}

	d3 := &models.Decision{
		Duration: &duration,
		ID:       3,
		Origin:   &source,
		Scenario: &scenario,
		Scope:    &scopeRange,
		Type:     &typ,
		Value:    &value3,
	}

	d4 := &models.Decision{
		Duration: &duration,
		ID:       4,
		Origin:   &source,
		Scenario: &scenario,
		Scope:    &scopeIP,
		Type:     &typ,
		Value:    &value4,
	}

	d5 := &models.Decision{
		Duration: &duration,
		ID:       5,
		Origin:   &source,
		Scenario: &scenario,
		Scope:    &scopeIP, // IP scope
		Type:     &typ,
		Value:    &value5, // range
	}

	s := newStore()
	err := s.add(d1)
	require.NoError(t, err)
	err = s.add(d2)
	require.NoError(t, err)
	err = s.add(d3)
	require.NoError(t, err)
	err = s.add(d4)
	require.NoError(t, err)
	err = s.add(d5)
	require.Error(t, err)

	ip1 := net.ParseIP(value1)
	r1, err := s.get(ip1)
	require.NoError(t, err)
	require.NotNil(t, r1)
	require.Equal(t, value1, *r1.Value)

	err = s.delete(d1)
	require.NoError(t, err)

	err = s.delete(d3)
	require.NoError(t, err)

	r1, err = s.get(ip1)
	require.NoError(t, err)
	require.Nil(t, r1)
}
