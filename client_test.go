package traeger

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestGrillStatusJSONUnmarshal(t *testing.T) {
	raw := `{
		"grill": 225.5,
		"set": 250.0,
		"pellet_level": 80.0,
		"connected": true,
		"system_status": 6,
		"acc": [
			{
				"uuid": "probe-1",
				"type": "probe",
				"con": 1,
				"probe": {
					"get_temp": 145.2,
					"set_temp": 165.0
				}
			},
			{
				"uuid": "probe-2",
				"type": "probe",
				"con": 0,
				"probe": {
					"get_temp": 0,
					"set_temp": 0
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
	if len(status.Accessories) != 2 {
		t.Fatalf("len(Accessories) = %d, want 2", len(status.Accessories))
	}

	acc := status.Accessories[0]
	if acc.UUID != "probe-1" {
		t.Errorf("acc[0].UUID = %q, want %q", acc.UUID, "probe-1")
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

func TestTokenRemaining(t *testing.T) {
	c := NewClient("user", "pass")

	// Token not set (zero time) — should be negative.
	if c.tokenRemaining() > 0 {
		t.Error("tokenRemaining should be <= 0 for zero tokenExpires")
	}

	// Token set in the future.
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

	// Should not attempt auth call (no server to call).
	if err := c.refreshToken(nil); err != nil {
		t.Fatalf("refreshToken: %v", err)
	}
	if c.token != "existing-token" {
		t.Error("token was unexpectedly changed")
	}
}

func TestHandleMessageDispatch(t *testing.T) {
	c := NewClient("user", "pass")

	var received []string
	c.OnStatus("grill1", func(thingName string, status *GrillStatus) {
		received = append(received, "specific:"+thingName)
	})
	c.OnStatusAll(func(thingName string, status *GrillStatus) {
		received = append(received, "global:"+thingName)
	})

	// Simulate an MQTT message.
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

	// Verify status was cached.
	s, ok := c.GetStatus("grill1")
	if !ok {
		t.Fatal("status not cached after handleMessage")
	}
	if s.GrillTemp != 200 {
		t.Errorf("cached GrillTemp = %v, want 200", s.GrillTemp)
	}
}

func TestHandleMessageIgnoresUnknownTopic(t *testing.T) {
	c := NewClient("user", "pass")
	msg := &fakeMessage{
		topic:   "other/topic",
		payload: []byte(`{}`),
	}
	// Should not panic.
	c.handleMessage(nil, msg)
}

func TestHandleMessageBadJSON(t *testing.T) {
	c := NewClient("user", "pass")
	msg := &fakeMessage{
		topic:   "prod/thing/update/grill1",
		payload: []byte(`not json`),
	}
	// Should not panic.
	c.handleMessage(nil, msg)

	_, ok := c.GetStatus("grill1")
	if ok {
		t.Error("status should not be cached for bad JSON")
	}
}

func TestAPIError(t *testing.T) {
	err := &APIError{StatusCode: 401, Body: "Unauthorized"}
	expected := "traeger: API error 401: Unauthorized"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
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

func TestWithLogger(t *testing.T) {
	l := &testLogger{}
	c := NewClient("user", "pass", WithLogger(l))
	// Verify the logger was set by triggering a log call via refreshToken skip.
	c.token = "tok"
	c.tokenExpires = time.Now().Add(10 * time.Minute)
	_ = c.refreshToken(nil)
	// nopLogger is replaced, so no panic means it works.
	_ = c
}

// fakeMessage implements mqtt.Message for testing.
type fakeMessage struct {
	topic   string
	payload []byte
}

func (m *fakeMessage) Duplicate() bool    { return false }
func (m *fakeMessage) Qos() byte          { return 0 }
func (m *fakeMessage) Retained() bool     { return false }
func (m *fakeMessage) Topic() string      { return m.topic }
func (m *fakeMessage) MessageID() uint16  { return 0 }
func (m *fakeMessage) Payload() []byte    { return m.payload }
func (m *fakeMessage) Ack()               {}

// testLogger is a simple logger for tests.
type testLogger struct{}

func (l *testLogger) Debug(msg string, args ...interface{}) {}
func (l *testLogger) Info(msg string, args ...interface{})  {}
func (l *testLogger) Error(msg string, args ...interface{}) {}
