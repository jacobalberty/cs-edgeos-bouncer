package xedgeos

import (
	"fmt"
	"log"
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
	i, has := slices.BinarySearch(a.Address, ip)
	if has {
		return false
	}

	a.Address = slices.Insert(a.Address, i, ip)

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

// This function compares the Address Group from our colleciton with the input group
// And returns data that does not exist in the input but does exist in our collection
// To be used for set it returns them in batches of 50
func (a *AddressGroupCollection) GetSetData(group *AddressGroup) ([]map[string]any, error) {
	var (
		batchSize = 50
		setGroup  = AddressGroup{}
	)

	// Get the group from the collection
	ourGroup, ok := (*a)[group.Name]
	if !ok {
		return nil, fmt.Errorf("group %s not found", group.Name)
	}

	// Find the difference between the two groups
	for _, ip := range group.Address {
		if !ourGroup.Contains(ip) {
			setGroup.Address = append(setGroup.Address, ip)
		}
	}

	batches := len(setGroup.Address) / batchSize
	if len(setGroup.Address)%batchSize != 0 {
		batches++
	}
	// Batch the results out
	data := make([]map[string]any, batches)
	for i := 0; i < batches; i++ {
		start := i * batchSize
		end := (i + 1) * batchSize
		if end > len(setGroup.Address) {
			end = len(setGroup.Address)
		}

		data[i] = map[string]any{
			"firewall": map[string]any{
				"group": map[string]any{
					"address-group": map[string]any{
						group.Name: map[string]any{
							"address": setGroup.Address[start:end],
						},
					},
				},
			},
		}
	}

	return data, nil
}

// This function compares the Address Group from our colleciton with the input group
// And returns data that does not exist in the input but does exist in our collection
// To be used for deletion it returns htem in batches of 50
func (a *AddressGroupCollection) GetDeleteData(group *AddressGroup) ([]map[string]any, error) {
	var (
		batchSize = 50
		delGroup  = AddressGroup{}
	)

	if !slices.IsSorted(group.Address) {
		log.Printf("sorting %s\n", group.Name)
		slices.Sort(group.Address)
	}

	// Get the group from the collection
	ourGroup, ok := (*a)[group.Name]
	if !ok {
		return nil, fmt.Errorf("group %s not found", group.Name)
	}

	// Find the difference between the two groups
	for _, ip := range ourGroup.Address {
		if !group.Contains(ip) {
			delGroup.Address = append(delGroup.Address, ip)
		}
	}

	batches := len(delGroup.Address) / batchSize
	if len(delGroup.Address)%batchSize != 0 {
		batches++
	}
	// Batch the results out
	data := make([]map[string]any, batches)
	for i := 0; i < batches; i++ {
		start := i * batchSize
		end := (i + 1) * batchSize
		if end > len(delGroup.Address) {
			end = len(delGroup.Address)
		}

		data[i] = map[string]any{
			"firewall": map[string]any{
				"group": map[string]any{
					"address-group": map[string]any{
						group.Name: map[string]any{
							"address": delGroup.Address[start:end],
						},
					},
				},
			},
		}
	}
	return data, nil
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
		slices.Sort(addresSlice)
		addressGroups[k] = AddressGroup{
			Name:    k,
			Address: addresSlice,
		}

	}

	return &addressGroups, nil
}
