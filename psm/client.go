package psm

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
)

type Config struct {
	User     string
	Password string
	Server   string
	SID      string // Store the SID cookie passed back from PSM Authentication
	Insecure bool   // Skip SSL verification if using an unsigned SSL Certificate
}

func (c *Config) Authenticate() error {
	// Create a map with the credentials as defined in the Terraform Provider.
	credentials := map[string]string{
		"username": c.User,
		"password": c.Password,
		"tenant":   "default", //Do we need to allow for a different tenant here?
	}

	// Convert provided credentials to JSON to pass to the login URL below
	jsonData, err := json.Marshal(credentials)
	if err != nil {
		return err
	}

	// Authenticate the user, passing the JSON that has been construsted. Ultimatly we need to grab the sid cookie
	// that PSM will return to us and store this for subsequent communication.
	req, err := http.NewRequest("POST", c.Server+"/v1/login", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json") // Specify that we're sending JSON to the PSM server, not just basic authentication

	client := c.Client()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// check if the authentication was successful
	if resp.StatusCode != http.StatusOK {
		return errors.New("authentication failed")
	}

	// Retrieve the sid cookie that PSM presents if authentication is successful
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "sid" {
			c.SID = cookie.Value
			break
		}
	}

	if c.SID == "" {
		return errors.New("sid cookie not found")
	}

	return nil
}

func (c *Config) Client() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: c.Insecure},
	}
	return &http.Client{Transport: tr}
}
