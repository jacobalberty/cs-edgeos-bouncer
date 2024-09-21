package xedgeos

import (
	"fmt"
	"slices"
)

type AddressGroups struct {
	in map[string]any
}

type GroupList []string

func (a *GroupList) Add(ip string) bool {
	if a.Contains(ip) {
		return false
	}
	*a = append(*a, ip)
	return true
}

func (a *GroupList) Contains(ip string) bool {
	_, has := slices.BinarySearch(*a, ip)
	return has
}
func (a *GroupList) Remove(ip string) bool {
	pos, has := slices.BinarySearch(*a, ip)
	if !has {
		return false
	}
	*a = append((*a)[:pos], (*a)[pos+1:]...)

	return true
}

func (a *AddressGroups) UpdateGroup(name string, group GroupList) error {
	tmp := a.in

	path := []string{"GET", "firewall", "group", "address-group", name}
	for _, p := range path {
		if tmp[p] == nil {
			return fmt.Errorf("path %v not found", path)
		}
		tmp = tmp[p].(map[string]any)
	}

	tmp["address"] = group

	return nil
}

func (a *AddressGroups) GetGroup(name string) (GroupList, error) {
	tmp := a.in

	path := []string{"GET", "firewall", "group", "address-group", name}
	for _, p := range path {
		if tmp[p] == nil {
			return nil, fmt.Errorf("path %v not found", path)
		}
		tmp = tmp[p].(map[string]any)
	}

	anyGroup, _ := tmp["address"].([]interface{})

	group := make([]string, len(anyGroup))
	for i, v := range anyGroup {
		group[i] = v.(string)
	}

	return group, nil
}

func NewAddressGroups(in map[string]any) *AddressGroups {
	return &AddressGroups{in: in}
}
