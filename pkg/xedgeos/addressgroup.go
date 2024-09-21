package xedgeos

import (
	"fmt"
	"slices"
)

type AddressGroups map[string]any

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
	tmp, ok := (*a)[name].(map[string]any)
	if !ok {
		return fmt.Errorf("group %s not found", name)
	}

	tmp["address"] = group
	(*a)[name].(map[string]any)["address"] = group

	return nil
}

func (a *AddressGroups) GetGroup(name string) (GroupList, error) {
	tmp, ok := (*a)[name].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("group %s not found", name)
	}

	anyGroup, _ := tmp["address"].([]interface{})

	group := make([]string, len(anyGroup))
	for i, v := range anyGroup {
		group[i] = v.(string)
	}

	return group, nil
}

func NewAddressGroups(in map[string]any) (*AddressGroups, error) {
	tmp := in

	path := []string{"GET", "firewall", "group", "address-group"}
	for _, p := range path {
		if tmp[p] == nil {
			return nil, fmt.Errorf("path %v not found", path)
		}
		tmp = tmp[p].(map[string]any)
	}

	addressGroups := AddressGroups(tmp)
	return &addressGroups, nil
}
