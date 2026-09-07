// Copyright 2026 Herman Slatman
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
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestDecision returns a minimally valid decision of the provided type,
// identified by id so that ties can be told apart.
func newTestDecision(id int64, typ string) *models.Decision {
	var (
		scope    = "Ip"
		value    = "127.0.0.1"
		duration = "120s"
		origin   = "cscli"
	)

	return &models.Decision{
		ID:       id,
		Duration: &duration,
		Origin:   &origin,
		Scope:    &scope,
		Type:     &typ,
		Value:    &value,
	}
}

func Test_remediationFrom(t *testing.T) {
	tests := []struct {
		typ  string
		want remediation
	}{
		{"allow", remediationAllow},
		{"captcha", remediationCaptcha},
		{"throttle", remediationThrottle},
		{"ban", remediationBan},
		{"mfa", remediationUnknown},
		{"", remediationUnknown},
		{"BAN", remediationUnknown}, // CrowdSec emits lowercase types
	}

	for _, tt := range tests {
		t.Run(tt.typ, func(t *testing.T) {
			assert.Equal(t, tt.want, remediationFrom(tt.typ))
		})
	}
}

func Test_remediationOrdering(t *testing.T) {
	// A captcha can be solved, so it must never shadow another remediation.
	assert.Less(t, remediationAllow, remediationCaptcha)
	assert.Less(t, remediationCaptcha, remediationThrottle)
	assert.Less(t, remediationThrottle, remediationUnknown)
	assert.Less(t, remediationUnknown, remediationBan)
}

func Test_selectDecision(t *testing.T) {
	tests := []struct {
		name      string
		decisions []*models.Decision
		wantID    int64 // 0 means "expect nil"
	}{
		{
			name:      "empty",
			decisions: []*models.Decision{},
			wantID:    0,
		},
		{
			name:      "nil slice",
			decisions: nil,
			wantID:    0,
		},
		{
			name:      "single decision",
			decisions: []*models.Decision{newTestDecision(1, "ban")},
			wantID:    1,
		},
		{
			name: "ban wins over captcha",
			decisions: []*models.Decision{
				newTestDecision(1, "captcha"),
				newTestDecision(2, "ban"),
			},
			wantID: 2,
		},
		{
			name: "ban wins over captcha regardless of order",
			decisions: []*models.Decision{
				newTestDecision(1, "ban"),
				newTestDecision(2, "captcha"),
			},
			wantID: 1,
		},
		{
			name: "throttle wins over captcha",
			decisions: []*models.Decision{
				newTestDecision(1, "captcha"),
				newTestDecision(2, "throttle"),
			},
			wantID: 2,
		},
		{
			name: "ban wins over throttle",
			decisions: []*models.Decision{
				newTestDecision(1, "throttle"),
				newTestDecision(2, "ban"),
			},
			wantID: 2,
		},
		{
			name: "unknown type wins over captcha",
			decisions: []*models.Decision{
				newTestDecision(1, "captcha"),
				newTestDecision(2, "mfa"),
			},
			wantID: 2,
		},
		{
			name: "ban wins over unknown type",
			decisions: []*models.Decision{
				newTestDecision(1, "mfa"),
				newTestDecision(2, "ban"),
			},
			wantID: 2,
		},
		{
			name: "captcha wins over allow",
			decisions: []*models.Decision{
				newTestDecision(1, "allow"),
				newTestDecision(2, "captcha"),
			},
			wantID: 2,
		},
		{
			name: "ties keep the first decision",
			decisions: []*models.Decision{
				newTestDecision(1, "ban"),
				newTestDecision(2, "ban"),
			},
			wantID: 1,
		},
		{
			name: "nil entries are skipped",
			decisions: []*models.Decision{
				nil,
				newTestDecision(1, "captcha"),
			},
			wantID: 1,
		},
		{
			name: "invalid entries are skipped",
			decisions: []*models.Decision{
				{ID: 99}, // no Scope, Value or Type
				newTestDecision(1, "captcha"),
			},
			wantID: 1,
		},
		{
			name: "only invalid entries",
			decisions: []*models.Decision{
				nil,
				{ID: 99},
			},
			wantID: 0,
		},
		{
			name: "strictest of many",
			decisions: []*models.Decision{
				newTestDecision(1, "captcha"),
				newTestDecision(2, "throttle"),
				newTestDecision(3, "ban"),
				newTestDecision(4, "captcha"),
			},
			wantID: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectDecision(tt.decisions)

			if tt.wantID == 0 {
				assert.Nil(t, got)
				return
			}

			require.NotNil(t, got)
			assert.Equal(t, tt.wantID, got.ID)
		})
	}
}
