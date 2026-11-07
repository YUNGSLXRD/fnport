package main

import "github.com/YUNGSLXRD/fnport/windows/internal/qos"

// Full replies from four independently bound sockets, in two spaced rounds.
// A single successful port says nothing about every other port or a new TTL.
func fullCheckTTL(replies []int) bool {
	if len(replies) != 4 {
		return false
	}
	for _, n := range replies {
		if qos.Got(n) < qos.PassMin {
			return false
		}
	}
	return true
}
func selectCheckTTL(lo, hi, current int, preserve bool, scan *fakeScan, probe func(int) []int) (string, int, int) {
	scan.Steps = nil
	scan.KillControl = nil
	order := []int{}
	if current >= 1 && current <= 16 {
		order = append(order, current)
	}
	for t := lo; t <= hi; t++ {
		if t != current {
			order = append(order, t)
		}
	}
	partial, previous, silentRun := 0, 0, 0
	attempted := 0
	for _, ttl := range order {
		first := probe(ttl)
		all := append([]int(nil), first...)
		if len(first) == 2 && (ttl == current || qos.Count(first, "pass") > 0) {
			second := probe(ttl)
			// A missing socket or failed second round cannot be hidden by concatenation.
			all = append(all, second...)
		}
		scan.Steps = append(scan.Steps, ttlReplies{ttl, all})
		attempted += len(all)
		if fullCheckTTL(all) {
			return "works", ttl, ttl
		}
		if qos.Count(all, "pass") > 0 {
			if partial == 0 {
				partial = ttl
			}
			if ttl == current && preserve {
				return "partial", ttl, 0
			}
		}
		silent := len(all) >= 2 && qos.Count(all, "silent") == len(all)
		if silent {
			if ttl == previous+1 {
				silentRun++
			} else {
				silentRun = 1
			}
		} else {
			silentRun = 0
		}
		previous = ttl
		if silentRun >= 2 {
			control := probe(0)
			scan.KillControl = append([]int(nil), control...)
			// Both baseline sockets must still answer substantially. Otherwise the
			// beacon itself may be limiting replies and cannot implicate the fake.
			if len(control) == 2 && qos.Got(control[0]) >= qos.FrozenMin && qos.Got(control[1]) >= qos.FrozenMin {
				if partial != 0 {
					return "partial", partial, 0
				}
				return "kills", 0, 0
			}
			if partial != 0 {
				return "partial", partial, 0
			}
			return "unclear", 0, 0
		}
	}
	if partial != 0 {
		return "partial", partial, 0
	}
	if attempted == 0 {
		return "unclear", 0, 0
	}
	return "fails", 0, 0
}
