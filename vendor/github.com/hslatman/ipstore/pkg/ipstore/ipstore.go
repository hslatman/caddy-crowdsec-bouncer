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

package ipstore

import (
	"fmt"
	"net"

	cr "github.com/yl2chen/cidranger"
)

// IPStore is a (simple) Key/Value store using IPs and CIDRs as keys
type IPStore struct {
	trie cr.Ranger
}

type entry struct {
	net   net.IPNet
	value interface{}
}

func (e entry) Network() net.IPNet {
	return e.net
}

// New returns a new instance of IPStore
func New() *IPStore {
	return &IPStore{
		trie: cr.NewPCTrieRanger(),
	}
}

// Add adds a new entry to the store mapped by net.IP
func (s *IPStore) Add(key net.IP, value interface{}) error {
	net := determineNetForIP(key)
	return s.AddCIDR(net, value)
}

// AddCIDR adds a new entry to the store mapped by net.IPNet
func (s *IPStore) AddCIDR(key net.IPNet, value interface{}) error {
	entry := entry{
		net:   key,
		value: value,
	}
	return s.trie.Insert(entry)
}

// AddIPOrCIDR adds an IP or CIDR
func (s *IPStore) AddIPOrCIDR(ipOrCIDR string, value interface{}) error {
	// TODO: implementation
	return nil
}

// Remove removes entry associated with net.IP from store
func (s *IPStore) Remove(key net.IP) (interface{}, error) {
	net := determineNetForIP(key)
	return s.RemoveCIDR(net)
}

// RemoveCIDR removes entry associated with net.IPNet from store
func (s *IPStore) RemoveCIDR(key net.IPNet) (interface{}, error) {
	re, err := s.trie.Remove(key)
	if err != nil {
		return nil, err
	}
	e, ok := re.(entry)
	if !ok {
		return nil, fmt.Errorf("error in type assertion")
	}
	return e.value, nil
}

// RemoveIPOrCIDR adds an IP or CIDR
func (s *IPStore) RemoveIPOrCIDR(ipOrCIDR string, value interface{}) (interface{}, error) {
	// TODO: implementation
	return nil, nil
}

// Contains returns whether an entry is available for the net.IP
func (s *IPStore) Contains(ip net.IP) (bool, error) {
	return s.trie.Contains(ip)
}

// Get returns entry from the store if it's available
func (s *IPStore) Get(key net.IP) ([]interface{}, error) {
	r, err := s.trie.ContainingNetworks(key)
	if err != nil {
		return nil, err
	}
	var result []interface{}
	for _, re := range r {
		e, _ := re.(entry) // type is guarded by Add/AddCIDR
		result = append(result, e.value)
	}
	return result, nil
}

// GetCIDR returns entry from the store if it's available
func (s *IPStore) GetCIDR(key net.IPNet) ([]interface{}, error) {
	// TODO: is this correct implementation? It's not exactly matching this CIDR, but all that are below it (too).
	r, err := s.trie.CoveredNetworks(key)
	if err != nil {
		return nil, err
	}
	var result []interface{}
	for _, re := range r {
		e, _ := re.(entry) // type is guarded by Add/AddCIDR
		result = append(result, e.value)
	}
	return result, nil
}

// Len returns the number of entries in the store
func (s *IPStore) Len() int {
	return s.trie.Len()
}

func determineNetForIP(ip net.IP) net.IPNet {
	isIPv4 := isIPv4(ip)
	maskSize := 128
	if isIPv4 {
		maskSize = 32
	}
	_, net, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), maskSize))
	return *net
}

func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}
