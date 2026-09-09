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
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// remediation ranks a CrowdSec decision type by how strictly it is
// enforced. An IP can be covered by several decisions at once — its own
// and any number of ranges containing it — and only one of them can be
// served, so they have to be comparable.
//
// The order matters: the highest value wins.
type remediation uint8

const (
	// remediationAllow is never emitted as a decision by CrowdSec, but
	// ranking it lowest means it can never shadow an enforcing decision.
	remediationAllow remediation = iota
	// remediationCaptcha ranks below every other enforcing remediation
	// because it can be solved: serving it grants access, so it must
	// never take precedence over a decision that doesn't.
	remediationCaptcha
	remediationThrottle
	// remediationUnknown covers types this bouncer doesn't handle
	// explicitly. WriteResponse serves them as a ban, so they rank
	// just below one.
	remediationUnknown
	remediationBan
)

// remediationFrom maps a CrowdSec decision type to its rank. Types are
// matched exactly; CrowdSec emits them lowercased.
func remediationFrom(typ string) remediation {
	switch typ {
	case "allow":
		return remediationAllow
	case "captcha":
		return remediationCaptcha
	case "throttle":
		return remediationThrottle
	case "ban":
		return remediationBan
	default:
		return remediationUnknown
	}
}

// selectDecision returns the strictest of the decisions provided,
// skipping any that are nil or missing the fields required to act on
// them. Decisions of equal rank are resolved to the first one seen. It
// returns nil if there's nothing to act upon.
func selectDecision(decisions []*models.Decision) *models.Decision {
	var (
		selected *models.Decision
		rank     remediation
	)

	for _, decision := range decisions {
		if isInvalid(decision) {
			continue
		}

		if r := remediationFrom(*decision.Type); selected == nil || r > rank {
			selected, rank = decision, r
		}
	}

	return selected
}
