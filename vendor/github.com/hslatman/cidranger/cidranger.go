/*
Package cidranger provides utility to store CIDR blocks and perform ip
inclusion tests against it.

To create a new instance of the path-compressed trie:

			ranger := NewPCTrieRanger()

To insert or remove an entry (any object that satisfies the RangerEntry
interface):

			_, network, _ := net.ParseCIDR("192.168.0.0/24")
			ranger.Insert(NewBasicRangerEntry(*network))
			ranger.Remove(network)

If you desire for any value to be attached to the entry, simply
create custom struct that satisfies the RangerEntry interface:

			type RangerEntry interface {
				Network() net.IPNet
			}

To test whether an IP is contained in the constructed networks ranger:

			// returns bool, error
			containsBool, err := ranger.Contains(net.ParseIP("192.168.0.1"))

To get a list of CIDR blocks in constructed ranger that contains IP:

			// returns []RangerEntry, error
			entries, err := ranger.ContainingNetworks(net.ParseIP("192.168.0.1"))

To get a list of all IPv4/IPv6 rangers respectively:

			// returns []RangerEntry, error
			entries, err := ranger.CoveredNetworks(*AllIPv4)
			entries, err := ranger.CoveredNetworks(*AllIPv6)

*/
package cidranger

import (
	"container/list"
	"fmt"
	"net"

	rnet "github.com/hslatman/cidranger/net"
)

// ErrInvalidNetworkInput is returned upon invalid network input.
var ErrInvalidNetworkInput = fmt.Errorf("Invalid network input")

// ErrInvalidNetworkNumberInput is returned upon invalid network input.
var ErrInvalidNetworkNumberInput = fmt.Errorf("Invalid network number input")

// AllIPv4 is a IPv4 CIDR that contains all networks
var AllIPv4 = parseCIDRUnsafe("0.0.0.0/0")

// AllIPv6 is a IPv6 CIDR that contains all networks
var AllIPv6 = parseCIDRUnsafe("0::0/0")

func parseCIDRUnsafe(s string) *net.IPNet {
	_, cidr, _ := net.ParseCIDR(s)
	return cidr
}

// RangerEntry is an interface for insertable entry into a Ranger.
type RangerEntry interface {
	Network() net.IPNet
}

type basicRangerEntry struct {
	ipNet net.IPNet
}

func (b *basicRangerEntry) Network() net.IPNet {
	return b.ipNet
}

// NewBasicRangerEntry returns a basic RangerEntry that only stores the network
// itself.
func NewBasicRangerEntry(ipNet net.IPNet) RangerEntry {
	return &basicRangerEntry{
		ipNet: ipNet,
	}
}

// Ranger is an interface for cidr block containment lookups.
type Ranger interface {
	// Insert a RangerEntry
	Insert(entry RangerEntry) error
	// Remove a network from the Ranger, returning its RangerEntry
	Remove(network net.IPNet) (RangerEntry, error)
	// ContainsNetwork returns true if the ip is covered in the Ranger
	Contains(ip net.IP) (bool, error)
	// ContainsNetwork returns true if the exact network is in the Ranger
	ContainsNetwork(network net.IPNet) (bool, error)
	// ContainingNetworks returns all RangerEntry that contain ip
	ContainingNetworks(ip net.IP) ([]RangerEntry, error)
	// CoveredNetworks returns all networks that are subnets of network
	CoveredNetworks(network net.IPNet) ([]RangerEntry, error)
	// Len returns number of entries in the Ranger
	Len() int
	// String returns a representation for visualization and debugging
	String() string
	// MissingNetworks determines the list of CIDR blocks out of the
	// address space which are not contained in the Ranger
	MissingNetworks() ([]net.IPNet, error)
}

// NewPCTrieRanger returns a versionedRanger that supports both IPv4 and IPv6
// using the path compressed trie implemention.
func NewPCTrieRanger() Ranger {
	return newVersionedRanger(newPrefixTree)
}

// NewIPv4PCTrieRanger returns an IPv4-only Ranger for use-cases where the additional
// version checking and second Trie overhead is not desired.
func NewIPv4PCTrieRanger() Ranger {
	return newPrefixTree(rnet.IPv4)
}

// Util function to leverage the subnet method on std lib net.IPNets
// If prefixlen is 0, return the immediate subnets, e.g. /15->/16
func Subnets(base net.IPNet, prefixlen int) (subnets []net.IPNet, err error) {
	network := rnet.NewNetwork(base)
	subnetworks, err := network.Subnet(prefixlen)
	if err != nil {
		return
	}
	for _, subnet := range subnetworks {
		subnets = append(subnets, subnet.IPNet)
	}
	return
}

// RangerIter is an interface to use with an iterator-like pattern
// ri := NewBredthIter(ptrie)
// for ri.Next() {
//     entry := ri.Get()
//     ...
// }
// if err := ri.Error(); err != nil {
//     ...
// }
// While it's not really an iterator, this is exactly what bufio.Scanner does.
// Basically the idea is to have an Error() method which you call after
// iteration is complete to see whether iteration terminated because it was done
// or because an error was encountered midway through.
type RangerIter interface {
	Next() bool
	Get() RangerEntry
	Error() error
}

type bredthRangerIter struct {
	path    *list.List
	node    *prefixTrie
	shallow bool
}

// A bredth-first iterator that returns all netblocks with a RangerEntry
func NewBredthIter(r Ranger) bredthRangerIter {
	return newBredthIter(r, false)
}

// A bredth-first iterator that will return only the largest netblocks with an entry
func NewShallowBredthIter(r Ranger) bredthRangerIter {
	return newBredthIter(r, true)
}
func newBredthIter(r Ranger, shallow bool) bredthRangerIter {
	root, ok := r.(*prefixTrie)
	if !ok {
		panic(fmt.Errorf("Invalid type for bredthRangerIter"))
	}
	iter := bredthRangerIter{
		node:    root,
		path:    list.New(),
		shallow: shallow,
	}
	iter.path.PushBack(root)
	return iter
}

func (i *bredthRangerIter) Next() bool {
	for i.path.Len() > 0 {
		element := i.path.Front()
		i.path.Remove(element)
		i.node = element.Value.(*prefixTrie)
		if i.shallow && i.node.hasEntry() {
			return true
		}
		for _, child := range i.node.children {
			if child != nil {
				i.path.PushBack(child)
			}
		}
		if i.node.hasEntry() {
			return true
		}
	}
	return false
}

func (i *bredthRangerIter) Get() RangerEntry {
	return i.node.entry
}

func (i *bredthRangerIter) Error() error {
	return nil
}

// Rollup apply
// Insert an entry at the parent of one or two children with entries, where the
// RangerEntry objects at those children meet the criteria of a rollup function
type RollupApply interface {
	// Decides if siblings should be rolled up
	CanRollup(child0 RangerEntry, child1 RangerEntry) bool
	// Rolls up siblings into a parent entry
	GetParentEntry(child0 RangerEntry, child1 RangerEntry, parentNet net.IPNet) RangerEntry
}

// Use a provided RollupApply and return the Ranger after modification
func DoRollupApply(r Ranger, f RollupApply) (Ranger, error) {
	trie, ok := r.(*prefixTrie)
	if !ok {
		return r, fmt.Errorf("DoRollupApply only implemented for prefixTrie-type Ranger")
	}
	// 1. Depth-first with a depth-stack?
	// 2. determine all new entries
	// 3. Insert all new entries
	// 4. repeat 1. until no new entries generated
	// Repeated traversal with entries between should be O(N*log(N))
	// Doing this because of the path-compression optimization and how new nodes are
	// inserted. If the entire tree was guaranteed to be filled-in, this could be O(N)?
	for entries := getRollupEntries(trie, f); len(entries) > 0; entries = getRollupEntries(trie, f) {
		for _, entry := range entries {
			err := trie.Insert(entry)
			if err != nil {
				return r, err
			}
		}
	}
	return r, nil
}

func getRollupEntries(trie *prefixTrie, f RollupApply) []RangerEntry {
	rollupEntries := []RangerEntry{}
	depth := list.New()
	depth.PushBack(trie)
	for depth.Len() > 0 {
		element := depth.Back()
		depth.Remove(element)
		node := element.Value.(*prefixTrie)
		nchildren := node.childrenCount()
		// Dead-end or already filled
		if nchildren == 0 {
			continue
		}
		// Need to check path of child if empty, BUT don't come back to this node
		if nchildren == 1 {
			child := node.children[0]
			if child == nil {
				child = node.children[1]
			}
			if !child.hasEntry() {
				depth.PushBack(child)
			}
			continue
		}
		// If both have an entry, check to rollup
		if node.children[0].hasEntry() && node.children[1].hasEntry() {
			if f.CanRollup(node.children[0].entry, node.children[1].entry) {
				rollupEntries = append(rollupEntries,
					f.GetParentEntry(node.children[0].entry, node.children[1].entry, node.network.IPNet),
				)
			}
			continue
		}
		// Visit children that don't have an entry, left depth-first
		for _, bit := range []int{1, 0} {
			if !node.children[bit].hasEntry() {
				depth.PushBack(node.children[bit])
			}
		}
	}
	return rollupEntries
}
