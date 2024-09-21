package xedgeos

import "astuart.co/edgeos-rest/pkg/edgeos"

func FromClient(c *edgeos.Client, err error) (*Client, error) {
	if err != nil {
		return nil, err
	}
	return &Client{Client: c}, nil
}

type Client struct {
	*edgeos.Client
}

func (c *Client) Set(data any) (edgeos.Resp, error) {
	return c.Client.GetJSON("set", data)
}
