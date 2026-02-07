package traeger

import (
	"context"
	"net/http"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/google/uuid"
)

// StatusHandler is called when a grill status update is received.
type StatusHandler func(thingName string, status *GrillStatus)

// Logger is a pluggable logging interface. Users can adapt slog, zap, etc.
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// nopLogger is the default logger that discards all output.
type nopLogger struct{}

func (nopLogger) Debug(string, ...interface{}) {}
func (nopLogger) Info(string, ...interface{})  {}
func (nopLogger) Error(string, ...interface{}) {}

// Client is the Traeger API and MQTT client.
type Client struct {
	username string
	password string

	httpClient *http.Client
	mqttClient mqtt.Client
	mqttUUID   string

	token          string
	tokenExpires   time.Time
	mqttURL        string
	mqttURLExpires time.Time

	grills []Grill
	status map[string]*GrillStatus

	handlers       map[string][]StatusHandler
	globalHandlers []StatusHandler

	mu     sync.RWMutex
	logger Logger

	tokenRefreshBuffer  time.Duration
	statusUpdateTimeout time.Duration
	connected           bool
	done                chan struct{}

	// Internal URL overrides for testing.
	authURL string
	apiURL  string
}

// Option configures the Client.
type Option func(*Client)

// WithHTTPClient sets a custom HTTP client for API requests.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) {
		cl.httpClient = c
	}
}

// WithMQTTClientID sets a custom MQTT client ID instead of a random UUID.
func WithMQTTClientID(id string) Option {
	return func(cl *Client) {
		cl.mqttUUID = id
	}
}

// WithTokenRefreshBuffer sets how far before expiry the token is refreshed.
// Default is 60 seconds.
func WithTokenRefreshBuffer(d time.Duration) Option {
	return func(cl *Client) {
		cl.tokenRefreshBuffer = d
	}
}

// WithStatusUpdateTimeout sets the timeout for waiting on MQTT status updates
// after sending a command. Default is 10 seconds.
func WithStatusUpdateTimeout(d time.Duration) Option {
	return func(cl *Client) {
		cl.statusUpdateTimeout = d
	}
}

// WithLogger sets a structured logger for the client.
func WithLogger(l Logger) Option {
	return func(cl *Client) {
		cl.logger = l
	}
}

// NewClient creates a new Traeger client. Call Connect to authenticate and start
// receiving grill updates.
func NewClient(username, password string, opts ...Option) *Client {
	c := &Client{
		username:            username,
		password:            password,
		mqttUUID:            uuid.New().String(),
		httpClient:          &http.Client{Timeout: 10 * time.Second},
		status:              make(map[string]*GrillStatus),
		handlers:            make(map[string][]StatusHandler),
		logger:              nopLogger{},
		tokenRefreshBuffer:  60 * time.Second,
		statusUpdateTimeout: 10 * time.Second,
		authURL:             authEndpoint,
		apiURL:              apiBaseURL,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Connect authenticates with Traeger, discovers grills, and starts the MQTT
// connection for real-time status updates.
func (c *Client) Connect(ctx context.Context) error {
	c.logger.Info("authenticating with Traeger")
	if err := c.refreshToken(ctx); err != nil {
		return err
	}

	c.logger.Info("discovering grills")
	grills, err := c.getGrills(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.grills = grills
	c.mu.Unlock()
	c.logger.Info("found grills", "count", len(grills))

	c.logger.Info("connecting to MQTT")
	if err := c.connectMQTT(ctx); err != nil {
		return err
	}

	if err := c.subscribeToGrills(); err != nil {
		return err
	}

	c.mu.Lock()
	c.connected = true
	c.done = make(chan struct{})
	c.mu.Unlock()

	go c.mqttKeepAlive()

	c.logger.Info("connected successfully")
	return nil
}

// Close disconnects the MQTT client and cleans up resources.
func (c *Client) Close() error {
	c.mu.Lock()
	if !c.connected {
		c.mu.Unlock()
		return nil
	}
	c.connected = false
	close(c.done)
	if c.mqttClient != nil && c.mqttClient.IsConnected() {
		c.mqttClient.Disconnect(250)
	}
	c.mu.Unlock()
	c.logger.Info("disconnected")
	return nil
}

// Grills returns the discovered grills.
func (c *Client) Grills() []Grill {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Grill, len(c.grills))
	copy(out, c.grills)
	return out
}

// GrillByName looks up a grill by its friendly name.
func (c *Client) GrillByName(name string) (*Grill, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, g := range c.grills {
		if g.FriendlyName == name {
			return &g, nil
		}
	}
	return nil, ErrGrillNotFound
}

// GetStatus returns the cached MQTT status for a grill. The second return value
// indicates whether a status was available.
func (c *Client) GetStatus(thingName string) (*GrillStatus, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.status[thingName]
	return s, ok
}

// OnStatus registers a handler for status updates from a specific grill.
func (c *Client) OnStatus(thingName string, handler StatusHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers[thingName] = append(c.handlers[thingName], handler)
}

// OnStatusAll registers a handler for status updates from all grills.
func (c *Client) OnStatusAll(handler StatusHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.globalHandlers = append(c.globalHandlers, handler)
}
