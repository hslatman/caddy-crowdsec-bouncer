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

	cr "github.com/hslatman/cidranger"
)

// Store is a (simple) Key/Value store using IPs and CIDRs as keys
type Store struct {
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
func New() *Store {
	return &Store{
		trie: cr.NewPCTrieRanger(),
	}
}

// Add adds a new entry to the store mapped by net.IP
func (s *Store) Add(key net.IP, value interface{}) error {

	net, err := determineNetForIP(key)
	if err != nil {
		return err
	}

	return s.AddCIDR(net, value)
}

// AddCIDR adds a new entry to the store mapped by net.IPNet
func (s *Store) AddCIDR(key net.IPNet, value interface{}) error {

	entry := entry{
		net:   key,
		value: value,
	}

	return s.trie.Insert(entry)
}

// AddIPOrCIDR adds an IP or CIDR
func (s *Store) AddIPOrCIDR(ipOrCIDR string, value interface{}) error {
	// TODO: implementation
	return nil
}

// Remove removes entry associated with net.IP from store
func (s *Store) Remove(key net.IP) (interface{}, error) {

	net, err := determineNetForIP(key)
	if err != nil {
		return nil, err
	}

	return s.RemoveCIDR(net)
}

// RemoveCIDR removes entry associated with net.IPNet from store
func (s *Store) RemoveCIDR(key net.IPNet) (interface{}, error) {

	re, err := s.trie.Remove(key)
	if err != nil {
		return nil, err
	}

	if re == nil {
		return nil, nil
	}

	e, ok := re.(entry)
	if !ok {
		return nil, fmt.Errorf("error in type assertion")
	}

	return e.value, nil
}

// RemoveIPOrCIDR adds an IP or CIDR
func (s *Store) RemoveIPOrCIDR(ipOrCIDR string, value interface{}) (interface{}, error) {
	// TODO: implementation
	return nil, nil
}

// Contains returns whether an entry is available for the net.IP
func (s *Store) Contains(ip net.IP) (bool, error) {
	return s.trie.Contains(ip)
}

// Get returns entries from the store based on the key net.IP
// Because multiple CIDRs may contain the key, we return a slice
// of entries instead of a single entry.
func (s *Store) Get(key net.IP) ([]interface{}, error) {

	r, err := s.trie.ContainingNetworks(key)
	if err != nil {
		return nil, err
	}

	// return all networks that this IP is part by reverse looping through the result
	// haven't fully deduced it yet, but it seems that the order of the entries from ContainingNetworks
	// are from biggest CIDR to smallest CIDR. I think the most logical thing to do is to return the
	// most specific CIDR that the net.IP is part of first instead of last, so that's why the
	// returned slice of interface{} is reversed.
	// TODO: verify that this is correct?
	var result []interface{}
	for i := len(r) - 1; i >= 0; i-- {
		e, _ := r[i].(entry) // type is guarded by Add/AddCIDR
		result = append(result, e.value)
	}

	return result, nil
}

// GetCIDR returns entry from the store if it's available
func (s *Store) GetCIDR(key net.IPNet) ([]interface{}, error) {

	// TODO: decide if we only want to return a single interface{}, because a specific CIDR should only exist once now

	// first perform exact match of the network
	t, err := s.trie.ContainsNetwork(key)
	if err != nil {
		return nil, err
	}

	// TODO: decide if we want to keep the check above; we could also call CoveredNetworks and just loop.
	// The additional call to ContainsNetwork was the reason I forked the original library, so we might
	// be able to return to using the original instead of the fork at github.com/hslatman/cidranger.
	// There are also changes in other forks that may be of interest, though ...

	// return with empty result if there's no exact match
	if !t {
		return nil, nil
	}

	// get all covered networks, including the exact match (if it exists) and smaller CIDR ranges
	r, err := s.trie.CoveredNetworks(key)
	if err != nil {
		return nil, err
	}

	// loop through the results and do a full equality check on the IP and IPMask
	var result []interface{}
	for _, re := range r {
		e, _ := re.(entry)                            // type is guarded by Add/AddCIDR
		keyMaskOnes, keyMaskZeroes := key.Mask.Size() // TODO: improve the equality check? Is what we do here correct?
		entryMaskOnes, entryMaskZeroes := e.net.Mask.Size()
		if key.IP.Equal(e.net.IP) && keyMaskOnes == entryMaskOnes && keyMaskZeroes == entryMaskZeroes {
			result = append(result, e.value)
		}
	}

	return result, nil
}

// Len returns the number of entries in the store
func (s *Store) Len() int {
	return s.trie.Len()
}

const ipv4MaskSize = 32
const ipv6MaskSize = 128

func determineNetForIP(ip net.IP) (net.IPNet, error) {

	if isIPv4(ip) {
		_, net, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), ipv4MaskSize))
		return *net, err
	}

	if isIPv6(ip) {
		_, net, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), ipv6MaskSize))
		return *net, err
	}

	return net.IPNet{}, fmt.Errorf("ip %s not a valid IPv4 or IPv6 address", ip.String())
}

func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

func isIPv6(ip net.IP) bool {
	return ip.To16() != nil
}
