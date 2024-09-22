package xedgeos

import (
	"fmt"
	"slices"
)

type AddressGroupCollection map[string]AddressGroup

type AddressGroup struct {
	Name    string   `json:"-"`
	Address []string `json:"address,omitempty"`
}

func (a *AddressGroup) Reset() {
	a.Address = []string{}
}

func (a *AddressGroup) Add(ip string) bool {
	if a.Contains(ip) {
		return false
	}
	a.Address = append(a.Address, ip)
	return true
}

func (a *AddressGroup) Contains(ip string) bool {
	_, has := slices.BinarySearch(a.Address, ip)
	return has
}

func (a *AddressGroup) Remove(ip string) bool {
	pos, has := slices.BinarySearch(a.Address, ip)
	if !has {
		return false
	}
	a.Address = append((a.Address)[:pos], (a.Address)[pos+1:]...)

	return true
}

func (a *AddressGroup) GetDeleteData() map[string]any {
	return map[string]any{
		"firewall": map[string]any{
			"group": map[string]any{
				"address-group": map[string]any{
					a.Name: map[string]any{
						"address": nil,
					},
				},
			},
		},
	}
}

// Returns address groups in batches of 50
func (a *AddressGroup) GetSetData() []map[string]any {
	batchSize := 1000
	batches := len(a.Address) / batchSize
	if len(a.Address)%batchSize != 0 {
		batches++
	}

	data := make([]map[string]any, batches)
	for i := 0; i < batches; i++ {
		start := i * batchSize
		end := (i + 1) * batchSize
		if end > len(a.Address) {
			end = len(a.Address)
		}

		data[i] = map[string]any{
			"firewall": map[string]any{
				"group": map[string]any{
					"address-group": map[string]any{
						a.Name: map[string]any{
							"address": a.Address[start:end],
						},
					},
				},
			},
		}
	}
	return data
}

func (a *AddressGroupCollection) UpdateGroup(group *AddressGroup) error {
	_, ok := (*a)[group.Name]
	if !ok {
		return fmt.Errorf("group %s not found", group.Name)
	}

	(*a)[group.Name] = *group

	return nil
}

func (a *AddressGroupCollection) GetGroup(name string) (*AddressGroup, error) {
	tmp, ok := (*a)[name]
	if !ok {
		return nil, fmt.Errorf("group %s not found", name)
	}

	tmp.Name = name

	return &tmp, nil
}

func NewAddressGroups(in map[string]any) (*AddressGroupCollection, error) {
	tmp := in

	path := []string{"GET", "firewall", "group", "address-group"}
	for _, p := range path {
		if tmp[p] == nil {
			return nil, fmt.Errorf("path %v not found", path)
		}
		tmp = tmp[p].(map[string]any)
	}

	addressGroups := AddressGroupCollection{}

	for k, v := range tmp {
		vmap, ok := v.(map[string]any)["address"].([]interface{})
		if !ok {
			vmap = make([]interface{}, 0)
		}
		addresSlice := make([]string, len(vmap))
		for i, a := range vmap {
			addresSlice[i] = a.(string)
		}
		addressGroups[k] = AddressGroup{
			Name:    k,
			Address: addresSlice,
		}

	}

	return &addressGroups, nil
}
