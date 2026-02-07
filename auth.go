package traeger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const authEndpoint = "https://auth-api.iot.traegergrills.io/tokens"

// tokenRemaining returns the time until the current token expires.
func (c *Client) tokenRemaining() time.Duration {
	return time.Until(c.tokenExpires)
}

// refreshToken proactively refreshes the auth token when it is within the
// refresh buffer of expiry.
func (c *Client) refreshToken(ctx context.Context) error {
	if c.tokenRemaining() > c.tokenRefreshBuffer {
		return nil
	}

	c.logger.Debug("refreshing auth token")
	requestTime := time.Now()

	result, err := c.authenticate(ctx)
	if err != nil {
		return err
	}

	c.token = result.IdToken
	c.tokenExpires = requestTime.Add(time.Duration(result.ExpiresIn) * time.Second)
	c.logger.Debug("token refreshed", "expires_in", c.tokenRemaining().String())
	return nil
}

// authenticate performs the Traeger auth API call and returns the token response.
func (c *Client) authenticate(ctx context.Context) (*authResponse, error) {
	reqBody := authRequest{
		Username: c.username,
		Password: c.password,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("traeger: marshal auth request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.authURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("traeger: create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("traeger: auth request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("traeger: read auth response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s", ErrAuthFailed, string(body))
	}

	var result authResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("traeger: unmarshal auth response: %w", err)
	}

	if result.IdToken == "" {
		return nil, fmt.Errorf("%w: no token in response", ErrAuthFailed)
	}

	return &result, nil
}
