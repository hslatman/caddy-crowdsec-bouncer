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

package crowdsec

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	iradix "github.com/hashicorp/go-immutable-radix"
	"go.uber.org/zap"
)

type lookupKey []byte

// NewBouncer creates a new (streaming) Bouncer with a storage based on immutable radix tree
func NewBouncer(apiKey, apiURL, tickerInterval string, logger *zap.Logger) (*Bouncer, error) {
	return &Bouncer{
		streamingBouncer: &csbouncer.StreamBouncer{
			APIKey:         apiKey,
			APIUrl:         apiURL,
			TickerInterval: tickerInterval,
			UserAgent:      "caddy-cs-bouncer",
		},
		store:  iradix.New(),
		logger: logger,
	}, nil
}

// Bouncer is a custom CrowdSec bouncer backed by an immutable radix tree
type Bouncer struct {
	streamingBouncer *csbouncer.StreamBouncer
	store            *iradix.Tree // TODO: I think we need separate stores for IPv4 and IPv6 to work correct
	logger           *zap.Logger
}

// Init initializes the Bouncer
func (b *Bouncer) Init() error {
	return b.streamingBouncer.Init()
}

// Run starts the Bouncer processes
func (b *Bouncer) Run() {

	// TODO: handle errors? Return it to caller?

	go func() error {
		b.logger.Info("start processing new and deleted decisions ...")
		for {
			select {
			// TODO: handle the process quitting
			// case <-t.Dying():
			// 	c.logger.Info("terminating bouncer process")
			// 	return nil
			case decisions := <-b.streamingBouncer.Stream:
				b.logger.Debug(fmt.Sprintf("processing %d deleted decisions", len(decisions.Deleted)))
				// TODO: deletions seem to include all old decisions that had already expired; CrowdSec bug or intended behavior?
				for _, decision := range decisions.Deleted {
					if err := b.Delete(decision); err != nil {
						b.logger.Error(fmt.Sprintf("unable to delete decision for '%s': %s", *decision.Value, err))
					} else {
						b.logger.Debug(fmt.Sprintf("deleted '%s'", *decision.Value))
					}
				}
				b.logger.Debug(fmt.Sprintf("processing %d added decisions", len(decisions.New)))
				for _, decision := range decisions.New {
					if err := b.Add(decision); err != nil {
						b.logger.Error(fmt.Sprintf("unable to insert decision for '%s': %s", *decision.Value, err))
					} else {
						b.logger.Debug(fmt.Sprintf("Adding '%s' for '%s'", *decision.Value, *decision.Duration))
					}
				}
			}
		}
	}()

	// TODO: handle connection errors in here? Soft or hard fail? Reconnects?
	go b.streamingBouncer.Run()
}

// ShutDown stops the Bouncer
func (b *Bouncer) ShutDown() error {
	// TODO: persist the current state of the radix tree in some way, so that it can be used in startup again?
	b.store = nil
	return nil
}

// Add adds a Decision to the storage
func (b *Bouncer) Add(decision *models.Decision) error {

	// TODO: provide additional ways for storing the decisions
	// (i.e. radix tree is not always the most efficient one, but it's great for matching IPs to ranges)
	// Knowing that a key is a CIDR does allow to check an IP with the .Contains() function, but still
	// requires looping through the ranges

	lookupKey, err := calculateLookupKeyFromDecision(decision)
	if err != nil {
		return err
	}

	// TODO: store lookup as number instead? Will that work with longest prefix lookup?
	// TODO: store additional data about the decision (i.e. time added to store, etc)
	newRoot, _, _ := b.store.Insert(lookupKey, decision)

	b.store = newRoot

	return nil
}

// Delete removes a Decision from the storage
func (b *Bouncer) Delete(decision *models.Decision) error {

	lookupKey, err := calculateLookupKeyFromDecision(decision)
	if err != nil {
		return err
	}

	// TODO: delete prefix instead for safety?
	newRoot, _, _ := b.store.Delete(lookupKey)

	b.store = newRoot

	return nil
}

// IsAllowed checks if an IP is allowed or not
func (b *Bouncer) IsAllowed(ip net.IP) (bool, *models.Decision, error) {

	// TODO: perform lookup in explicit allowlist as a kind of quick lookup in front of the CrowdSec lookup list?

	maskSize := 32
	lookupKey := calculateLookupKeyFromIP(ip, maskSize)
	_, value, found := b.store.Root().LongestPrefix(lookupKey)

	if found {
		v, ok := value.(*models.Decision)
		if !ok {
			return false, nil, fmt.Errorf("wrong type in storage: %T", value)
		}

		return false, v, nil
	}

	return true, nil, nil
}

func serializeDecision(decision *models.Decision) (string, error) {
	serbyte, err := json.Marshal(decision)
	if err != nil {
		return "", fmt.Errorf("serialize error : %s", err)
	}
	return string(serbyte), nil
}

func calculateLookupKeyFromDecision(decision *models.Decision) (lookupKey, error) {

	var ipOrPrefix lookupKey
	scope := *decision.Scope

	// TODO: handle IPv6 in addition to IPv4

	switch scope {
	case "Ip":
		ip := net.ParseIP(*decision.Value)
		if ip != nil {
			ipOrPrefix = calculateLookupKeyFromIP(ip, 32) // TODO: IPv6 support.
		}
	case "Range":
		ip, ipNet, err := net.ParseCIDR(*decision.Value)
		if err == nil && ipNet != nil && ip != nil {
			ipNet.Contains(ip)
			ones, bits := ipNet.Mask.Size()
			fmt.Println(ones, bits) // TODO: bits can be used for IPv6 vs IPv4?
			ipOrPrefix = calculateLookupKeyFromIP(ip, ones)
		}
	default:
		return nil, fmt.Errorf("got unhandled scope: %s", scope)
	}

	if ipOrPrefix == nil {
		return nil, errors.New("no IP or CIDR found to determine IP (prefix)")
	}

	return lookupKey(ipOrPrefix), nil
}

func calculateLookupKeyFromIP(ip net.IP, maskSize int) lookupKey {

	ia := Inet_Aton(ip) // TODO: IPv6 support.

	ipOrPrefix := fmt.Sprintf("%032s", strconv.FormatInt(ia, 2))
	ipOrPrefix = ipOrPrefix[0:maskSize]

	return lookupKey(ipOrPrefix)
}

// Inet_Aton converts an IPv4 net.IP object to a 64 bit integer.
func Inet_Aton(ip net.IP) int64 {
	ipv4Int := big.NewInt(0)
	ipv4Int.SetBytes(ip.To4())
	return ipv4Int.Int64()
}

// Inet6_Aton converts an IP Address (IPv4 or IPv6) net.IP object to a hexadecimal
// representaiton. This function is the equivalent of
// inet6_aton({{ ip address }}) in MySQL.
func Inet6_Aton(ip net.IP) string {
	ipv4 := false
	if ip.To4() != nil {
		ipv4 = true
	}

	ipInt := big.NewInt(0)
	if ipv4 {
		ipInt.SetBytes(ip.To4())
		ipHex := hex.EncodeToString(ipInt.Bytes())
		return ipHex
	}

	ipInt.SetBytes(ip.To16())
	ipHex := hex.EncodeToString(ipInt.Bytes())
	return ipHex
}
