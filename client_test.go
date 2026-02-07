package traeger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── Test helpers ─────────────────────────────────────────────────────

// fakeMessage implements mqtt.Message for testing.
type fakeMessage struct {
	topic   string
	payload []byte
}

func (m *fakeMessage) Duplicate() bool   { return false }
func (m *fakeMessage) Qos() byte         { return 0 }
func (m *fakeMessage) Retained() bool    { return false }
func (m *fakeMessage) Topic() string     { return m.topic }
func (m *fakeMessage) MessageID() uint16 { return 0 }
func (m *fakeMessage) Payload() []byte   { return m.payload }
func (m *fakeMessage) Ack()              {}

// testLogger captures log calls for verification.
type testLogger struct {
	debugCalls int
	infoCalls  int
	errorCalls int
}

func (l *testLogger) Debug(msg string, args ...interface{}) { l.debugCalls++ }
func (l *testLogger) Info(msg string, args ...interface{})  { l.infoCalls++ }
func (l *testLogger) Error(msg string, args ...interface{}) { l.errorCalls++ }

// newTestServer creates an httptest server that handles auth, users/self,
// commands, and mqtt-connections endpoints. Returns the server and a client
// pointed at it.
func newTestServer(t *testing.T) (*httptest.Server, *Client) {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req authRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Username == "bad" {
			http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(authResponse{
			AccessToken:  "access-tok",
			ExpiresIn:    86400,
			IdToken:      "test-id-token",
			RefreshToken: "refresh-tok",
			TokenType:    "Bearer",
		})
	})

	mux.HandleFunc("/users/self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(userDataResponse{
			Things: []Grill{
				{ThingName: "GRILL001", FriendlyName: "Test Grill"},
				{ThingName: "GRILL002", FriendlyName: "Patio Grill"},
			},
		})
	})

	mux.HandleFunc("/things/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/commands") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "{}")
	})

	mux.HandleFunc("/mqtt-connections", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(mqttConnectionResponse{
			SignedURL:         "wss://example.com/mqtt?sig=test",
			ExpirationSeconds: 3600,
		})
	})

	srv := httptest.NewServer(mux)

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.authURL = srv.URL + "/tokens"
	c.apiURL = srv.URL

	return srv, c
}

// ── Model tests ──────────────────────────────────────────────────────

func TestGrillStatusJSONUnmarshal(t *testing.T) {
	raw := `{
		"grill": 225.5,
		"set": 250.0,
		"pellet_level": 80.0,
		"connected": true,
		"system_status": 6,
		"ambient": 72,
		"keepwarm": 1,
		"smoke": 1,
		"units": 1,
		"acc": [
			{
				"uuid": "probe-1",
				"type": "probe",
				"channel": "p0",
				"con": 1,
				"probe": {
					"get_temp": 145.2,
					"set_temp": 165.0,
					"alarm_fired": 0
				}
			},
			{
				"uuid": "probe-2",
				"type": "probe",
				"channel": "p1",
				"con": 0,
				"probe": {
					"get_temp": 0,
					"set_temp": 0,
					"alarm_fired": 0
				}
			}
		]
	}`

	var status GrillStatus
	if err := json.Unmarshal([]byte(raw), &status); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if status.GrillTemp != 225.5 {
		t.Errorf("GrillTemp = %v, want 225.5", status.GrillTemp)
	}
	if status.SetTemp != 250.0 {
		t.Errorf("SetTemp = %v, want 250.0", status.SetTemp)
	}
	if status.PelletLevel != 80.0 {
		t.Errorf("PelletLevel = %v, want 80.0", status.PelletLevel)
	}
	if !status.Connected {
		t.Error("Connected = false, want true")
	}
	if status.SystemStatus != StatusCooking {
		t.Errorf("SystemStatus = %v, want %v", status.SystemStatus, StatusCooking)
	}
	if status.Ambient != 72 {
		t.Errorf("Ambient = %v, want 72", status.Ambient)
	}
	if status.KeepWarm != 1 {
		t.Errorf("KeepWarm = %v, want 1", status.KeepWarm)
	}
	if status.Smoke != 1 {
		t.Errorf("Smoke = %v, want 1", status.Smoke)
	}
	if status.Units != 1 {
		t.Errorf("Units = %v, want 1", status.Units)
	}
	if len(status.Accessories) != 2 {
		t.Fatalf("len(Accessories) = %d, want 2", len(status.Accessories))
	}

	acc := status.Accessories[0]
	if acc.UUID != "probe-1" {
		t.Errorf("acc[0].UUID = %q, want %q", acc.UUID, "probe-1")
	}
	if acc.Channel != "p0" {
		t.Errorf("acc[0].Channel = %q, want %q", acc.Channel, "p0")
	}
	if acc.Probe == nil {
		t.Fatal("acc[0].Probe is nil")
	}
	if acc.Probe.CurrentTemp != 145.2 {
		t.Errorf("acc[0].Probe.CurrentTemp = %v, want 145.2", acc.Probe.CurrentTemp)
	}
	if acc.Probe.TargetTemp != 165.0 {
		t.Errorf("acc[0].Probe.TargetTemp = %v, want 165.0", acc.Probe.TargetTemp)
	}
}

func TestGrillStatusProbes(t *testing.T) {
	status := GrillStatus{
		Accessories: []Accessory{
			{UUID: "p1", Type: "probe", Connected: 1, Probe: &ProbeData{CurrentTemp: 100}},
			{UUID: "p2", Type: "probe", Connected: 0, Probe: &ProbeData{}},
			{UUID: "other", Type: "fan", Connected: 1},
		},
	}

	probes := status.Probes()
	if len(probes) != 1 {
		t.Fatalf("Probes() returned %d, want 1", len(probes))
	}
	if probes[0].UUID != "p1" {
		t.Errorf("Probes()[0].UUID = %q, want %q", probes[0].UUID, "p1")
	}
}

func TestGrillStatusProbesEmpty(t *testing.T) {
	status := GrillStatus{}
	probes := status.Probes()
	if len(probes) != 0 {
		t.Errorf("Probes() returned %d, want 0", len(probes))
	}
}

func TestGrillJSONUnmarshal(t *testing.T) {
	raw := `{"thingName": "ABC123", "friendlyName": "My Grill"}`
	var g Grill
	if err := json.Unmarshal([]byte(raw), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if g.ThingName != "ABC123" {
		t.Errorf("ThingName = %q, want %q", g.ThingName, "ABC123")
	}
	if g.FriendlyName != "My Grill" {
		t.Errorf("FriendlyName = %q, want %q", g.FriendlyName, "My Grill")
	}
}

func TestUserDataResponseUnmarshal(t *testing.T) {
	raw := `{"things": [{"thingName": "G1", "friendlyName": "Grill One"}, {"thingName": "G2", "friendlyName": "Grill Two"}]}`
	var resp userDataResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Things) != 2 {
		t.Fatalf("len(Things) = %d, want 2", len(resp.Things))
	}
	if resp.Things[0].ThingName != "G1" {
		t.Errorf("Things[0].ThingName = %q, want %q", resp.Things[0].ThingName, "G1")
	}
}

func TestMQTTConnectionResponseUnmarshal(t *testing.T) {
	raw := `{"signedUrl": "wss://example.com/mqtt?sig=abc", "expirationSeconds": 3600}`
	var resp mqttConnectionResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.SignedURL != "wss://example.com/mqtt?sig=abc" {
		t.Errorf("SignedURL = %q, want correct URL", resp.SignedURL)
	}
	if resp.ExpirationSeconds != 3600 {
		t.Errorf("ExpirationSeconds = %v, want 3600", resp.ExpirationSeconds)
	}
}

func TestGrillUpdatePayloadUnmarshal(t *testing.T) {
	raw := `{"status": {"grill": 300, "set": 350, "pellet_level": 50, "connected": true, "system_status": 3, "acc": []}}`
	var payload grillUpdatePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	var status GrillStatus
	if err := json.Unmarshal(payload.Status, &status); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if status.GrillTemp != 300 {
		t.Errorf("GrillTemp = %v, want 300", status.GrillTemp)
	}
}

func TestAuthResponseUnmarshal(t *testing.T) {
	raw := `{"accessToken": "access.tok", "expiresIn": 86400, "idToken": "abc.def.ghi", "refreshToken": "refresh.tok", "tokenType": "Bearer"}`
	var resp authResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.IdToken != "abc.def.ghi" {
		t.Errorf("IdToken = %q, want %q", resp.IdToken, "abc.def.ghi")
	}
	if resp.ExpiresIn != 86400 {
		t.Errorf("ExpiresIn = %v, want 86400", resp.ExpiresIn)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", resp.TokenType, "Bearer")
	}
}

// ── SystemStatus tests ───────────────────────────────────────────────

func TestSystemStatusString(t *testing.T) {
	tests := []struct {
		status SystemStatus
		want   string
	}{
		{StatusSleeping, "sleeping"},
		{StatusIdle, "idle"},
		{StatusIgniting, "igniting"},
		{StatusPreheating, "preheating"},
		{StatusCooking, "cooking"},
		{StatusCustomCook, "custom_cook"},
		{StatusCoolDown, "cool_down"},
		{StatusShutdown, "shutdown"},
		{StatusOffline, "offline"},
		{SystemStatus(42), "unknown(42)"},
		{SystemStatus(0), "unknown(0)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.status.String()
			if got != tt.want {
				t.Errorf("SystemStatus(%d).String() = %q, want %q", tt.status, got, tt.want)
			}
		})
	}
}

// ── Client lifecycle tests ───────────────────────────────────────────

func TestNewClientDefaults(t *testing.T) {
	c := NewClient("user", "pass")
	if c.username != "user" {
		t.Errorf("username = %q, want %q", c.username, "user")
	}
	if c.password != "pass" {
		t.Errorf("password = %q, want %q", c.password, "pass")
	}
	if c.mqttUUID == "" {
		t.Error("mqttUUID should not be empty")
	}
	if c.tokenRefreshBuffer != 60*time.Second {
		t.Errorf("tokenRefreshBuffer = %v, want 60s", c.tokenRefreshBuffer)
	}
	if c.statusUpdateTimeout != 10*time.Second {
		t.Errorf("statusUpdateTimeout = %v, want 10s", c.statusUpdateTimeout)
	}
	if c.authURL != authEndpoint {
		t.Errorf("authURL = %q, want %q", c.authURL, authEndpoint)
	}
	if c.apiURL != apiBaseURL {
		t.Errorf("apiURL = %q, want %q", c.apiURL, apiBaseURL)
	}
}

func TestNewClientOptions(t *testing.T) {
	httpClient := &http.Client{Timeout: 30 * time.Second}
	c := NewClient("user", "pass",
		WithHTTPClient(httpClient),
		WithMQTTClientID("custom-id"),
		WithTokenRefreshBuffer(120*time.Second),
		WithStatusUpdateTimeout(30*time.Second),
	)

	if c.httpClient != httpClient {
		t.Error("WithHTTPClient did not apply")
	}
	if c.mqttUUID != "custom-id" {
		t.Errorf("mqttUUID = %q, want %q", c.mqttUUID, "custom-id")
	}
	if c.tokenRefreshBuffer != 120*time.Second {
		t.Errorf("tokenRefreshBuffer = %v, want 120s", c.tokenRefreshBuffer)
	}
	if c.statusUpdateTimeout != 30*time.Second {
		t.Errorf("statusUpdateTimeout = %v, want 30s", c.statusUpdateTimeout)
	}
}

func TestClose(t *testing.T) {
	c := NewClient("user", "pass")
	c.connected = true
	c.done = make(chan struct{})

	err := c.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if c.connected {
		t.Error("connected should be false after Close")
	}
}

func TestCloseWithNilMQTT(t *testing.T) {
	c := NewClient("user", "pass")
	c.connected = true
	c.done = make(chan struct{})
	c.mqttClient = nil

	err := c.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestCloseIdempotent(t *testing.T) {
	c := NewClient("user", "pass")
	c.connected = true
	c.done = make(chan struct{})

	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second close should be a no-op, not panic on double-close.
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// ── Grill query tests ────────────────────────────────────────────────

func TestGrillByName(t *testing.T) {
	c := NewClient("user", "pass")
	c.grills = []Grill{
		{ThingName: "A1", FriendlyName: "Backyard"},
		{ThingName: "B2", FriendlyName: "Garage"},
	}

	g, err := c.GrillByName("Backyard")
	if err != nil {
		t.Fatalf("GrillByName: %v", err)
	}
	if g.ThingName != "A1" {
		t.Errorf("ThingName = %q, want %q", g.ThingName, "A1")
	}

	_, err = c.GrillByName("Nonexistent")
	if err != ErrGrillNotFound {
		t.Errorf("err = %v, want ErrGrillNotFound", err)
	}
}

func TestGetStatus(t *testing.T) {
	c := NewClient("user", "pass")
	c.status["grill1"] = &GrillStatus{GrillTemp: 225}

	s, ok := c.GetStatus("grill1")
	if !ok {
		t.Fatal("GetStatus returned false for existing grill")
	}
	if s.GrillTemp != 225 {
		t.Errorf("GrillTemp = %v, want 225", s.GrillTemp)
	}

	_, ok = c.GetStatus("missing")
	if ok {
		t.Error("GetStatus returned true for missing grill")
	}
}

func TestGrills(t *testing.T) {
	c := NewClient("user", "pass")
	c.grills = []Grill{
		{ThingName: "A1", FriendlyName: "One"},
	}

	grills := c.Grills()
	if len(grills) != 1 {
		t.Fatalf("Grills() returned %d, want 1", len(grills))
	}

	// Verify it's a copy.
	grills[0].FriendlyName = "Modified"
	if c.grills[0].FriendlyName != "One" {
		t.Error("Grills() did not return a copy")
	}
}

func TestGrillsEmpty(t *testing.T) {
	c := NewClient("user", "pass")
	grills := c.Grills()
	if len(grills) != 0 {
		t.Errorf("Grills() returned %d, want 0", len(grills))
	}
}

// ── Auth tests ───────────────────────────────────────────────────────

func TestTokenRemaining(t *testing.T) {
	c := NewClient("user", "pass")

	if c.tokenRemaining() > 0 {
		t.Error("tokenRemaining should be <= 0 for zero tokenExpires")
	}

	c.tokenExpires = time.Now().Add(5 * time.Minute)
	remaining := c.tokenRemaining()
	if remaining < 4*time.Minute || remaining > 6*time.Minute {
		t.Errorf("tokenRemaining = %v, want ~5m", remaining)
	}
}

func TestRefreshTokenSkipsWhenFresh(t *testing.T) {
	c := NewClient("user", "pass")
	c.token = "existing-token"
	c.tokenExpires = time.Now().Add(10 * time.Minute)

	if err := c.refreshToken(context.Background()); err != nil {
		t.Fatalf("refreshToken: %v", err)
	}
	if c.token != "existing-token" {
		t.Error("token was unexpectedly changed")
	}
}

func TestAuthenticateSuccess(t *testing.T) {
	srv, c := newTestServer(t)
	defer srv.Close()

	ctx := context.Background()
	result, err := c.authenticate(ctx)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if result.IdToken != "test-id-token" {
		t.Errorf("IdToken = %q, want %q", result.IdToken, "test-id-token")
	}
	if result.ExpiresIn != 86400 {
		t.Errorf("ExpiresIn = %v, want 86400", result.ExpiresIn)
	}
}

func TestAuthenticateFailure(t *testing.T) {
	srv, c := newTestServer(t)
	defer srv.Close()
	c.username = "bad"

	ctx := context.Background()
	_, err := c.authenticate(ctx)
	if err == nil {
		t.Fatal("expected error for bad credentials")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("err = %v, want ErrAuthFailed", err)
	}
}

func TestAuthenticateEmptyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(authResponse{
			IdToken:   "",
			ExpiresIn: 86400,
		})
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.authURL = srv.URL

	_, err := c.authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("err = %v, want ErrAuthFailed", err)
	}
}

func TestAuthenticateBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json at all")
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.authURL = srv.URL

	_, err := c.authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func TestRefreshTokenCallsAuthenticate(t *testing.T) {
	srv, c := newTestServer(t)
	defer srv.Close()

	// Token is expired, so refreshToken should call authenticate.
	c.token = ""
	c.tokenExpires = time.Time{}

	err := c.refreshToken(context.Background())
	if err != nil {
		t.Fatalf("refreshToken: %v", err)
	}
	if c.token != "test-id-token" {
		t.Errorf("token = %q, want %q", c.token, "test-id-token")
	}
	if c.tokenExpires.IsZero() {
		t.Error("tokenExpires should be set")
	}
}

// ── API tests ────────────────────────────────────────────────────────

func TestDoAuthorizedRequestHeaders(t *testing.T) {
	var gotAuth, gotUA, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUA = r.Header.Get("User-Agent")
		gotCT = r.Header.Get("Content-Type")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.token = "my-token"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	resp, err := c.doAuthorizedRequest(context.Background(), "GET", srv.URL+"/test", nil)
	if err != nil {
		t.Fatalf("doAuthorizedRequest: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "my-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "my-token")
	}
	if gotUA != userAgent {
		t.Errorf("User-Agent = %q, want %q", gotUA, userAgent)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want %q", gotCT, "application/json")
	}
}

func TestDoAuthorizedRequestAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	_, err := c.doAuthorizedRequest(context.Background(), "GET", srv.URL+"/test", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", apiErr.StatusCode)
	}
}

func TestDoAuthorizedRequestRefreshesExpiredToken(t *testing.T) {
	srv, c := newTestServer(t)
	defer srv.Close()

	// Token is expired, so doAuthorizedRequest should refresh it.
	c.token = "expired"
	c.tokenExpires = time.Time{}

	resp, err := c.doAuthorizedRequest(context.Background(), "GET", srv.URL+"/users/self", nil)
	if err != nil {
		t.Fatalf("doAuthorizedRequest: %v", err)
	}
	resp.Body.Close()

	if c.token != "test-id-token" {
		t.Errorf("token = %q, want %q (should have been refreshed)", c.token, "test-id-token")
	}
}

func TestGetGrills(t *testing.T) {
	srv, c := newTestServer(t)
	defer srv.Close()

	// Pre-authenticate.
	c.token = "test-id-token"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	grills, err := c.getGrills(context.Background())
	if err != nil {
		t.Fatalf("getGrills: %v", err)
	}
	if len(grills) != 2 {
		t.Fatalf("len(grills) = %d, want 2", len(grills))
	}
	if grills[0].ThingName != "GRILL001" {
		t.Errorf("grills[0].ThingName = %q, want %q", grills[0].ThingName, "GRILL001")
	}
	if grills[1].FriendlyName != "Patio Grill" {
		t.Errorf("grills[1].FriendlyName = %q, want %q", grills[1].FriendlyName, "Patio Grill")
	}
}

func TestGetGrillsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.apiURL = srv.URL
	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	_, err := c.getGrills(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetGrillsBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.apiURL = srv.URL
	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	_, err := c.getGrills(context.Background())
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func TestSendCommand(t *testing.T) {
	var gotBody string
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		var m map[string]string
		json.Unmarshal(body, &m)
		gotBody = m["command"]
		fmt.Fprint(w, "{}")
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.apiURL = srv.URL
	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	err := c.sendCommand(context.Background(), "GRILL001", "11,225")
	if err != nil {
		t.Fatalf("sendCommand: %v", err)
	}
	if gotPath != "/things/GRILL001/commands" {
		t.Errorf("path = %q, want %q", gotPath, "/things/GRILL001/commands")
	}
	if gotBody != "11,225" {
		t.Errorf("command = %q, want %q", gotBody, "11,225")
	}
}

func TestSendCommandAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.apiURL = srv.URL
	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	err := c.sendCommand(context.Background(), "G1", "99")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetMQTTCredentials(t *testing.T) {
	srv, c := newTestServer(t)
	defer srv.Close()

	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	signedURL, expiresAt, err := c.getMQTTCredentials(context.Background())
	if err != nil {
		t.Fatalf("getMQTTCredentials: %v", err)
	}
	if signedURL != "wss://example.com/mqtt?sig=test" {
		t.Errorf("signedURL = %q", signedURL)
	}
	if time.Until(expiresAt) < 59*time.Minute {
		t.Errorf("expiresAt too soon: %v", expiresAt)
	}
}

func TestGetMQTTCredentialsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.apiURL = srv.URL
	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	_, _, err := c.getMQTTCredentials(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetMQTTCredentialsBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.apiURL = srv.URL
	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	_, _, err := c.getMQTTCredentials(context.Background())
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

// ── Typed command tests ──────────────────────────────────────────────

func TestSetTemperature(t *testing.T) {
	var gotCmd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]string
		json.Unmarshal(body, &m)
		gotCmd = m["command"]
		fmt.Fprint(w, "{}")
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.apiURL = srv.URL
	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	if err := c.SetTemperature(context.Background(), "G1", 225); err != nil {
		t.Fatalf("SetTemperature: %v", err)
	}
	if gotCmd != "11,225" {
		t.Errorf("command = %q, want %q", gotCmd, "11,225")
	}
}

func TestSetTimer(t *testing.T) {
	var gotCmd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]string
		json.Unmarshal(body, &m)
		gotCmd = m["command"]
		fmt.Fprint(w, "{}")
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.apiURL = srv.URL
	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	if err := c.SetTimer(context.Background(), "G1", 2*time.Hour); err != nil {
		t.Fatalf("SetTimer: %v", err)
	}
	if gotCmd != "12,07200" {
		t.Errorf("command = %q, want %q", gotCmd, "12,07200")
	}
}

func TestClearTimer(t *testing.T) {
	var gotCmd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]string
		json.Unmarshal(body, &m)
		gotCmd = m["command"]
		fmt.Fprint(w, "{}")
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.apiURL = srv.URL
	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	if err := c.ClearTimer(context.Background(), "G1"); err != nil {
		t.Fatalf("ClearTimer: %v", err)
	}
	if gotCmd != "13" {
		t.Errorf("command = %q, want %q", gotCmd, "13")
	}
}

func TestSetProbeTemperature(t *testing.T) {
	var gotCmd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]string
		json.Unmarshal(body, &m)
		gotCmd = m["command"]
		fmt.Fprint(w, "{}")
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.apiURL = srv.URL
	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	if err := c.SetProbeTemperature(context.Background(), "G1", 165); err != nil {
		t.Fatalf("SetProbeTemperature: %v", err)
	}
	if gotCmd != "14,165" {
		t.Errorf("command = %q, want %q", gotCmd, "14,165")
	}
}

func TestShutdown(t *testing.T) {
	var gotCmd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]string
		json.Unmarshal(body, &m)
		gotCmd = m["command"]
		fmt.Fprint(w, "{}")
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.apiURL = srv.URL
	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	if err := c.Shutdown(context.Background(), "G1"); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if gotCmd != "17" {
		t.Errorf("command = %q, want %q", gotCmd, "17")
	}
}

func TestSetKeepWarm(t *testing.T) {
	var gotCmds []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]string
		json.Unmarshal(body, &m)
		gotCmds = append(gotCmds, m["command"])
		fmt.Fprint(w, "{}")
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.apiURL = srv.URL
	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)
	ctx := context.Background()

	if err := c.SetKeepWarm(ctx, "G1", true); err != nil {
		t.Fatalf("SetKeepWarm(true): %v", err)
	}
	if err := c.SetKeepWarm(ctx, "G1", false); err != nil {
		t.Fatalf("SetKeepWarm(false): %v", err)
	}
	if len(gotCmds) != 2 {
		t.Fatalf("got %d commands, want 2", len(gotCmds))
	}
	if gotCmds[0] != "18" {
		t.Errorf("KeepWarm ON = %q, want %q", gotCmds[0], "18")
	}
	if gotCmds[1] != "19" {
		t.Errorf("KeepWarm OFF = %q, want %q", gotCmds[1], "19")
	}
}

func TestSetSuperSmoke(t *testing.T) {
	var gotCmds []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]string
		json.Unmarshal(body, &m)
		gotCmds = append(gotCmds, m["command"])
		fmt.Fprint(w, "{}")
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.apiURL = srv.URL
	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)
	ctx := context.Background()

	if err := c.SetSuperSmoke(ctx, "G1", true); err != nil {
		t.Fatalf("SetSuperSmoke(true): %v", err)
	}
	if err := c.SetSuperSmoke(ctx, "G1", false); err != nil {
		t.Fatalf("SetSuperSmoke(false): %v", err)
	}
	if len(gotCmds) != 2 {
		t.Fatalf("got %d commands, want 2", len(gotCmds))
	}
	if gotCmds[0] != "20" {
		t.Errorf("SuperSmoke ON = %q, want %q", gotCmds[0], "20")
	}
	if gotCmds[1] != "21" {
		t.Errorf("SuperSmoke OFF = %q, want %q", gotCmds[1], "21")
	}
}

func TestSendRawCommand(t *testing.T) {
	var gotCmd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]string
		json.Unmarshal(body, &m)
		gotCmd = m["command"]
		fmt.Fprint(w, "{}")
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.apiURL = srv.URL
	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	if err := c.SendRawCommand(context.Background(), "G1", "90"); err != nil {
		t.Fatalf("SendRawCommand: %v", err)
	}
	if gotCmd != "90" {
		t.Errorf("command = %q, want %q", gotCmd, "90")
	}
}

// ── RequestStatusUpdate tests ────────────────────────────────────────

func TestRequestStatusUpdateSuccess(t *testing.T) {
	srv, c := newTestServer(t)
	defer srv.Close()

	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)
	c.statusUpdateTimeout = 2 * time.Second

	// Simulate MQTT delivering status shortly after command is sent.
	go func() {
		time.Sleep(50 * time.Millisecond)
		msg := &fakeMessage{
			topic:   "prod/thing/update/GRILL001",
			payload: []byte(`{"status": {"grill": 225, "set": 250, "pellet_level": 70, "connected": true, "system_status": 6, "acc": []}}`),
		}
		c.handleMessage(nil, msg)
	}()

	status, err := c.RequestStatusUpdate(context.Background(), "GRILL001")
	if err != nil {
		t.Fatalf("RequestStatusUpdate: %v", err)
	}
	if status.GrillTemp != 225 {
		t.Errorf("GrillTemp = %v, want 225", status.GrillTemp)
	}
	if status.SystemStatus != StatusCooking {
		t.Errorf("SystemStatus = %v, want %v", status.SystemStatus, StatusCooking)
	}
}

func TestRequestStatusUpdateTimeout(t *testing.T) {
	srv, c := newTestServer(t)
	defer srv.Close()

	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)
	c.statusUpdateTimeout = 200 * time.Millisecond

	// No MQTT message will arrive.
	_, err := c.RequestStatusUpdate(context.Background(), "GRILL001")
	if err != ErrTimeout {
		t.Errorf("err = %v, want ErrTimeout", err)
	}
}

func TestRequestStatusUpdateContextCancelled(t *testing.T) {
	srv, c := newTestServer(t)
	defer srv.Close()

	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)
	c.statusUpdateTimeout = 5 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after a brief delay.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := c.RequestStatusUpdate(ctx, "GRILL001")
	if err != context.Canceled {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestRequestStatusUpdateContextDeadline(t *testing.T) {
	srv, c := newTestServer(t)
	defer srv.Close()

	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)
	c.statusUpdateTimeout = 5 * time.Second

	// Context with a short deadline (shorter than statusUpdateTimeout).
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := c.RequestStatusUpdate(ctx, "GRILL001")
	// Should get either context.DeadlineExceeded or ErrTimeout.
	if err == nil {
		t.Fatal("expected error")
	}
}

// ── MQTT handler tests ───────────────────────────────────────────────

func TestHandleMessageDispatch(t *testing.T) {
	c := NewClient("user", "pass")

	var received []string
	c.OnStatus("grill1", func(thingName string, status *GrillStatus) {
		received = append(received, "specific:"+thingName)
	})
	c.OnStatusAll(func(thingName string, status *GrillStatus) {
		received = append(received, "global:"+thingName)
	})

	msg := &fakeMessage{
		topic:   "prod/thing/update/grill1",
		payload: []byte(`{"status": {"grill": 200, "set": 250, "pellet_level": 70, "connected": true, "system_status": 6, "acc": []}}`),
	}
	c.handleMessage(nil, msg)

	if len(received) != 2 {
		t.Fatalf("received %d handler calls, want 2", len(received))
	}
	if received[0] != "specific:grill1" {
		t.Errorf("received[0] = %q, want %q", received[0], "specific:grill1")
	}
	if received[1] != "global:grill1" {
		t.Errorf("received[1] = %q, want %q", received[1], "global:grill1")
	}

	s, ok := c.GetStatus("grill1")
	if !ok {
		t.Fatal("status not cached after handleMessage")
	}
	if s.GrillTemp != 200 {
		t.Errorf("cached GrillTemp = %v, want 200", s.GrillTemp)
	}
}

func TestHandleMessageGlobalOnly(t *testing.T) {
	c := NewClient("user", "pass")

	var called bool
	c.OnStatusAll(func(thingName string, status *GrillStatus) {
		called = true
	})

	msg := &fakeMessage{
		topic:   "prod/thing/update/unknown-grill",
		payload: []byte(`{"status": {"grill": 100, "set": 200, "pellet_level": 50, "connected": true, "system_status": 3, "acc": []}}`),
	}
	c.handleMessage(nil, msg)

	if !called {
		t.Error("global handler should have been called")
	}
}

func TestHandleMessageIgnoresUnknownTopic(t *testing.T) {
	c := NewClient("user", "pass")
	msg := &fakeMessage{
		topic:   "other/topic",
		payload: []byte(`{}`),
	}
	c.handleMessage(nil, msg)
}

func TestHandleMessageBadJSON(t *testing.T) {
	c := NewClient("user", "pass")
	msg := &fakeMessage{
		topic:   "prod/thing/update/grill1",
		payload: []byte(`not json`),
	}
	c.handleMessage(nil, msg)

	_, ok := c.GetStatus("grill1")
	if ok {
		t.Error("status should not be cached for bad JSON")
	}
}

func TestHandleMessageBadStatusJSON(t *testing.T) {
	c := NewClient("user", "pass")
	msg := &fakeMessage{
		topic:   "prod/thing/update/grill1",
		payload: []byte(`{"status": "not an object"}`),
	}
	c.handleMessage(nil, msg)

	_, ok := c.GetStatus("grill1")
	if ok {
		t.Error("status should not be cached for bad status JSON")
	}
}

func TestHandleMessageFullPayload(t *testing.T) {
	c := NewClient("user", "pass")

	payload := `{"status": {
		"grill": 225, "set": 250, "pellet_level": 70, "connected": true,
		"system_status": 6, "ambient": 72, "probe": 145, "probe_set": 165,
		"probe_con": 1, "probe_alarm_fired": 0, "keepwarm": 0, "smoke": 1,
		"errors": 0, "grill_mode": 0, "cook_timer_start": 1000, "cook_timer_end": 2000,
		"cook_timer_complete": 0, "cook_id": "COOK123", "units": 1,
		"server_status": 1, "time": 1500, "in_custom": 0,
		"sys_timer_start": 900, "sys_timer_end": 1800, "sys_timer_complete": 0,
		"grease_level": 30, "grease_temperature": 150, "seasoned": 1, "uuid": "GRILL1",
		"acc": [{"uuid": "p0", "type": "probe", "channel": "p0", "con": 1,
			"probe": {"get_temp": 145, "set_temp": 165, "alarm_fired": 0}}]
	}}`

	msg := &fakeMessage{
		topic:   "prod/thing/update/grill1",
		payload: []byte(payload),
	}
	c.handleMessage(nil, msg)

	s, ok := c.GetStatus("grill1")
	if !ok {
		t.Fatal("status not cached")
	}
	if s.GrillTemp != 225 {
		t.Errorf("GrillTemp = %v, want 225", s.GrillTemp)
	}
	if s.Ambient != 72 {
		t.Errorf("Ambient = %v, want 72", s.Ambient)
	}
	if s.ProbeTemp != 145 {
		t.Errorf("ProbeTemp = %v, want 145", s.ProbeTemp)
	}
	if s.ProbeSetTemp != 165 {
		t.Errorf("ProbeSetTemp = %v, want 165", s.ProbeSetTemp)
	}
	if s.Smoke != 1 {
		t.Errorf("Smoke = %v, want 1", s.Smoke)
	}
	if s.CookTimerStart != 1000 {
		t.Errorf("CookTimerStart = %v, want 1000", s.CookTimerStart)
	}
	if s.CookID != "COOK123" {
		t.Errorf("CookID = %q, want %q", s.CookID, "COOK123")
	}
	if s.SysTimerStart != 900 {
		t.Errorf("SysTimerStart = %v, want 900", s.SysTimerStart)
	}
	if s.GreaseLevel != 30 {
		t.Errorf("GreaseLevel = %v, want 30", s.GreaseLevel)
	}
	if s.GreaseTemperature != 150 {
		t.Errorf("GreaseTemperature = %v, want 150", s.GreaseTemperature)
	}
	if s.Seasoned != 1 {
		t.Errorf("Seasoned = %v, want 1", s.Seasoned)
	}
	if s.UUID != "GRILL1" {
		t.Errorf("UUID = %q, want %q", s.UUID, "GRILL1")
	}

	probes := s.Probes()
	if len(probes) != 1 {
		t.Fatalf("Probes() = %d, want 1", len(probes))
	}
	if probes[0].Channel != "p0" {
		t.Errorf("probe channel = %q, want %q", probes[0].Channel, "p0")
	}
}

// ── Connect tests ────────────────────────────────────────────────────

func TestConnectAuthFailure(t *testing.T) {
	srv, c := newTestServer(t)
	defer srv.Close()
	c.username = "bad"

	err := c.Connect(context.Background())
	if err == nil {
		t.Fatal("expected auth error")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("err = %v, want ErrAuthFailed", err)
	}
}

func TestConnectGrillsFail(t *testing.T) {
	// Auth succeeds but grills endpoint fails.
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tokens" {
			json.NewEncoder(w).Encode(authResponse{
				IdToken:   "test-token",
				ExpiresIn: 86400,
			})
			return
		}
		if r.URL.Path == "/users/self" {
			callCount++
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.authURL = srv.URL + "/tokens"
	c.apiURL = srv.URL

	err := c.Connect(context.Background())
	if err == nil {
		t.Fatal("expected error from grills endpoint")
	}
	if callCount == 0 {
		t.Error("grills endpoint was never called")
	}
}

func TestConnectMQTTFails(t *testing.T) {
	srv, c := newTestServer(t)
	defer srv.Close()
	l := &testLogger{}
	c.logger = l

	// Connect will succeed through auth + grills, then fail at MQTT connect.
	// Use a short timeout so the MQTT connection attempt doesn't hang.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := c.Connect(ctx)
	// MQTT will fail because wss://example.com/mqtt isn't a real broker.
	if err == nil {
		t.Fatal("expected MQTT connection error")
	}
	// Auth and grill discovery should have succeeded (logged Info).
	if l.infoCalls < 3 {
		t.Errorf("expected at least 3 info calls (auth, grills, mqtt), got %d", l.infoCalls)
	}
	// Verify grills were discovered despite MQTT failure.
	grills := c.Grills()
	if len(grills) != 2 {
		t.Errorf("expected 2 grills discovered before MQTT failure, got %d", len(grills))
	}
}

// ── MQTT subscribe/connect tests ─────────────────────────────────────

func TestSubscribeToGrillsNotConnected(t *testing.T) {
	c := NewClient("user", "pass")
	c.mqttClient = nil

	err := c.subscribeToGrills()
	if err != ErrNotConnected {
		t.Errorf("err = %v, want ErrNotConnected", err)
	}
}

func TestMQTTKeepAliveSkipsWhenFresh(t *testing.T) {
	c := NewClient("user", "pass")
	c.done = make(chan struct{})
	c.mqttURLExpires = time.Now().Add(30 * time.Minute)

	// Close immediately so the goroutine exits after one tick.
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(c.done)
	}()
	c.mqttKeepAlive()

	// URL shouldn't have changed since it's still fresh.
	if c.mqttURL != "" {
		t.Errorf("mqttURL should be empty (unchanged), got %q", c.mqttURL)
	}
}

func TestMQTTKeepAliveStopsOnClose(t *testing.T) {
	c := NewClient("user", "pass")
	c.done = make(chan struct{})
	c.mqttURLExpires = time.Now().Add(30 * time.Minute)

	done := make(chan struct{})
	go func() {
		c.mqttKeepAlive()
		close(done)
	}()

	close(c.done)

	select {
	case <-done:
		// Goroutine exited as expected.
	case <-time.After(2 * time.Second):
		t.Fatal("mqttKeepAlive did not stop after done was closed")
	}
}

func TestCloseStopsKeepAlive(t *testing.T) {
	c := NewClient("user", "pass")
	c.done = make(chan struct{})
	c.connected = true
	c.mqttURLExpires = time.Now().Add(30 * time.Minute)

	exited := make(chan struct{})
	go func() {
		c.mqttKeepAlive()
		close(exited)
	}()

	// Let the goroutine start and capture the done channel.
	time.Sleep(10 * time.Millisecond)

	c.Close()

	select {
	case <-exited:
		// Goroutine exited as expected.
	case <-time.After(2 * time.Second):
		t.Fatal("mqttKeepAlive did not stop after Close")
	}
}

func TestReconnectMQTTCredentialsFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	c := NewClient("user", "pass", WithHTTPClient(srv.Client()))
	c.apiURL = srv.URL
	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	err := c.reconnectMQTT()
	if err == nil {
		t.Fatal("expected error when credentials fail")
	}
}

func TestReconnectMQTTConnectFails(t *testing.T) {
	srv, c := newTestServer(t)
	defer srv.Close()

	c.token = "tok"
	c.tokenExpires = time.Now().Add(1 * time.Hour)

	// reconnectMQTT will get valid credentials but fail to connect to
	// wss://example.com/mqtt (not a real broker).
	err := c.reconnectMQTT()
	if err == nil {
		t.Fatal("expected error when MQTT connect fails")
	}
	// Credentials should have been updated even though connect failed.
	if c.mqttURL != "wss://example.com/mqtt?sig=test" {
		t.Errorf("mqttURL = %q, want wss://example.com/mqtt?sig=test", c.mqttURL)
	}
}

func TestHandleConnect(t *testing.T) {
	l := &testLogger{}
	c := NewClient("user", "pass", WithLogger(l))
	// No MQTT client → subscribeToGrills will fail, but handleConnect
	// should log the error rather than panicking.
	c.handleConnect(nil)

	if l.infoCalls == 0 {
		t.Error("logger.Info should have been called")
	}
	if l.errorCalls == 0 {
		t.Error("logger.Error should have been called for subscribe failure")
	}
}

// ── Error type tests ─────────────────────────────────────────────────

func TestAPIError(t *testing.T) {
	err := &APIError{StatusCode: 401, Body: "Unauthorized"}
	expected := "traeger: API error 401: Unauthorized"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}

func TestAPIError500(t *testing.T) {
	err := &APIError{StatusCode: 500, Body: "Internal Server Error"}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("Error() should contain 500: %q", err.Error())
	}
}

// ── Logger tests ─────────────────────────────────────────────────────

func TestNopLogger(t *testing.T) {
	l := nopLogger{}
	// Should not panic.
	l.Debug("test", "key", "val")
	l.Info("test", "key", "val")
	l.Error("test", "key", "val")
}

func TestWithLogger(t *testing.T) {
	l := &testLogger{}
	c := NewClient("user", "pass", WithLogger(l))

	// Trigger some logging via handleMessage.
	msg := &fakeMessage{
		topic:   "prod/thing/update/grill1",
		payload: []byte(`{"status": {"grill": 200, "set": 250, "pellet_level": 70, "connected": true, "system_status": 6, "acc": []}}`),
	}
	c.handleMessage(nil, msg)

	if l.debugCalls == 0 {
		t.Error("logger.Debug should have been called")
	}
}

func TestLoggerCalledOnHandleMessage(t *testing.T) {
	l := &testLogger{}
	c := NewClient("user", "pass", WithLogger(l))

	msg := &fakeMessage{
		topic:   "prod/thing/update/grill1",
		payload: []byte(`{"status": {"grill": 200, "set": 250, "pellet_level": 70, "connected": true, "system_status": 6, "acc": []}}`),
	}
	c.handleMessage(nil, msg)

	if l.debugCalls == 0 {
		t.Error("logger.Debug should have been called during handleMessage")
	}
}

func TestLoggerCalledOnBadMessage(t *testing.T) {
	l := &testLogger{}
	c := NewClient("user", "pass", WithLogger(l))

	msg := &fakeMessage{
		topic:   "prod/thing/update/grill1",
		payload: []byte(`not json`),
	}
	c.handleMessage(nil, msg)

	if l.errorCalls == 0 {
		t.Error("logger.Error should have been called for bad JSON")
	}
}

// ── Event registration tests ─────────────────────────────────────────

func TestOnStatusMultipleHandlers(t *testing.T) {
	c := NewClient("user", "pass")

	count := 0
	c.OnStatus("g1", func(string, *GrillStatus) { count++ })
	c.OnStatus("g1", func(string, *GrillStatus) { count++ })
	c.OnStatusAll(func(string, *GrillStatus) { count++ })

	msg := &fakeMessage{
		topic:   "prod/thing/update/g1",
		payload: []byte(`{"status": {"grill": 200, "set": 250, "pellet_level": 70, "connected": true, "system_status": 6, "acc": []}}`),
	}
	c.handleMessage(nil, msg)

	if count != 3 {
		t.Errorf("handler count = %d, want 3", count)
	}
}
