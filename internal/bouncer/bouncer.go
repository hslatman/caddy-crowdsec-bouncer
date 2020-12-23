// Copyright 2020 Herman Slatman
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
	"encoding/json"
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"go.uber.org/zap"
)

func New(logger *zap.Logger) (*bouncer, error) {
	return &bouncer{
		logger: logger,
	}, nil
}

type bouncer struct {
	logger *zap.Logger
}

func (b *bouncer) Init() error {
	return nil
}

func (b *bouncer) Add(decision *models.Decision) error {
	b.logger.Info("adding ...")
	// banDuration, err := time.ParseDuration(*decision.Duration)
	// if err != nil {
	// 	return err
	// }
	// b.logger.Info("custom [%s] : add ban on %s for %s sec (%s)", c.path, *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario)

	// str, err := serializeDecision(decision)
	// if err != nil {
	// 	b.logger.Warning("serialize: %s", err)
	// }
	// cmd := exec.Command(c.path, "add", *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario, str)
	// if out, err := cmd.CombinedOutput(); err != nil {
	// 	b.logger.Info("Error in 'add' command (%s): %v --> %s", cmd.String(), err, string(out))
	// }
	return nil
}

func (b *bouncer) Delete(decision *models.Decision) error {
	b.logger.Info("deleting ...")
	// banDuration, err := time.ParseDuration(*decision.Duration)
	// if err != nil {
	// 	return err
	// }

	// str, err := serializeDecision(decision)
	// if err != nil {
	// 	b.logger.Warning("serialize: %s", err)
	// }
	// b.logger.Info("custom [%s] : del ban on %s for %s sec (%s)", c.path, *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario)
	// cmd := exec.Command(c.path, "del", *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario, str)
	// if out, err := cmd.CombinedOutput(); err != nil {
	// 	b.logger.Info("Error in 'del' command (%s): %v --> %s", cmd.String(), err, string(out))
	// }
	return nil
}

func (b *bouncer) ShutDown() error {
	return nil
}

func serializeDecision(decision *models.Decision) (string, error) {
	serbyte, err := json.Marshal(decision)
	if err != nil {
		return "", fmt.Errorf("serialize error : %s", err)
	}
	return string(serbyte), nil
}
