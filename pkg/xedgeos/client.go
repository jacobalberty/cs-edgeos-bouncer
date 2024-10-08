package xedgeos

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
)

// Scenario is just a string type to encourage the use of internal constants.
type Scenario string

// Common feature endpoints
const (
	PortForwarding Scenario = ".Port_Forwarding"
)

// A Client can interact with the EdgeOS REST API
type Client struct {
	Username, Password, Address string

	Path, Suffix, LoginEndpoint string

	cli *http.Client
}

// Endpoint provides a quick way to get a formatted string for an edgeos
// endpoint.
func (c *Client) Endpoint(s string) string {
	return fmt.Sprintf("%s/%s/%s%s", c.Address, c.Path, s, c.Suffix)
}

// Login sets up an http session with the EdgeOS device using the supplied
// endpoint and credentials
func (c *Client) Login() error {
	v := url.Values{
		"username": []string{c.Username},
		"password": []string{c.Password},
	}

	res, err := c.cli.PostForm(c.Address+"/"+c.LoginEndpoint, v)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}

// Resp is the basic response type for the EdgeOS API. Higher-level methods
// will tend to skip this type and return strongly-typed objects for specific
// endpoints.
type Resp map[string]interface{}

// GetJSON takes an endpoint and data for the POST body (or GET if `data` is nil) and
// returns the Resp type that contains the data response from the endpoint.
func (c *Client) GetJSON(endpoint string, data interface{}) (Resp, error) {
	var m map[string]interface{}

	err := c.JSONFor(endpoint, data, &m)

	return m, err
}

// DoFor wraps the http client's Do method for callers, writing the json to
// `out` and returning any errors encountered.
func (c *Client) DoFor(req *http.Request, out interface{}) error {
	res, err := c.cli.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()
	return json.NewDecoder(io.TeeReader(res.Body, os.Stdout)).Decode(out)
}

// JSONFor is a high-level method that takes an endpoint, a post body, and a
// pointer to a struct into which the JSON should be decoded.
func (c *Client) JSONFor(endpoint string, data, out interface{}) error {
	var (
		res *http.Response
		err error
	)
	if data == nil {
		res, err = c.cli.Get(c.Endpoint(endpoint))
	} else {
		bs, _ := json.Marshal(map[string]interface{}{"data": data})
		res, err = c.cli.Post(c.Endpoint(endpoint), "application/json", bytes.NewReader(bs))
	}

	if err != nil {
		return err
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(out)
}

// Get returns some standard configuration information from EdgeOS
func (c *Client) Get() (Resp, error) {
	return c.GetJSON("get", nil)
}

// Feature takes an EdgeOS "Scenario" as an argument and returns a Resp
// representing the JSON returned by the API.
func (c *Client) Feature(s Scenario) (Resp, error) {
	f, err := c.GetJSON("feature", map[string]string{
		"action":   "load",
		"scenario": string(s),
	})

	if err != nil {
		return Resp{}, err
	}

	return Resp(f["FEATURE"].(map[string]interface{})), nil
}

// FeatureFor takes a scenario and a pointer to a struct. The JSON response
// will be deserialized into the `out` object, and any errors will be returned.
func (c *Client) FeatureFor(s Scenario, out interface{}) error {
	return c.JSONFor("feature", map[string]string{
		"action":   "load",
		"scenario": string(s),
	}, out)
}

// SetFeature allows users to programmatically update features
func (c *Client) SetFeature(s Scenario, data interface{}) (Resp, error) {
	f, err := c.GetJSON("feature", map[string]interface{}{
		"action":   "apply",
		"apply":    data,
		"scenario": string(s),
	})
	if err != nil {
		return Resp{}, err
	}

	return Resp(f["FEATURE"].(map[string]interface{})), nil
}

// SetFeatureFor takes a "Scenario", some data to send, and a pointer to an
// interface into which the JSON response will be decoded.
func (c *Client) SetFeatureFor(s Scenario, data interface{}, out interface{}) error {
	return c.JSONFor("feature", map[string]interface{}{
		"action":   "apply",
		"apply":    data,
		"scenario": string(s),
	}, out)
}

// NewClient returns an initialized Client for interacting with an EdgeOS device
func NewClient(addr, username, password string) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	c := &Client{
		Username: username,
		Password: password,
		Path:     "api/edge",
		Suffix:   ".json",
		Address:  addr,
		cli: &http.Client{
			Transport: &csrfTransport{
				Referrer: addr,
			},
			Jar: jar,
		},
	}
	return c, nil
}
func (c *Client) Batch(data BatchData) (Resp, error) {
	var m map[string]interface{}

	bs, _ := json.Marshal(data)
	res, err := c.cli.Post(c.Endpoint("batch"), "application/json", bytes.NewReader(bs))

	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&m)

	return m, err
}

// Delete takes a map of data and sends it to the EdgeOS API
func (c *Client) Delete(data any) (Resp, error) {
	var m map[string]interface{}

	bs, _ := json.Marshal(data)
	res, err := c.cli.Post(c.Endpoint("delete"), "application/json", bytes.NewReader(bs))
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&m)

	return m, err
}

// Set takes a map of data and sends it to the EdgeOS API
func (c *Client) Set(data any) (Resp, error) {
	var m map[string]interface{}

	bs, _ := json.Marshal(data)
	res, err := c.cli.Post(c.Endpoint("set"), "application/json", bytes.NewReader(bs))

	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&m)

	return m, err
}

type BatchData struct {
	Set    map[string]interface{} `json:"SET"`
	Delete map[string]interface{} `json:"DELETE"`
}
