package cloudflare

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	cf "github.com/cloudflare/cloudflare-go"
)

// mockCF bildet die drei benötigten Cloudflare-Endpunkte nach: Zone suchen, A-Eintrag lesen, A-Eintrag ändern.
type mockCF struct {
	mu        sync.Mutex
	content   string
	patches   int
	lists     int
	failPatch bool
}

const info = `"result_info":{"page":1,"per_page":100,"count":1,"total_count":1,"total_pages":1}`

func (m *mockCF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/zones":
		fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":[{"id":"z1","name":"example.com"}],%s}`, info)
	case r.Method == http.MethodGet && r.URL.Path == "/zones/z1/dns_records":
		m.lists++
		fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":[{"id":"r1","type":"A","name":"home.example.com","content":%q,"proxied":false,"ttl":60}],%s}`, m.content, info)
	case (r.Method == http.MethodPatch || r.Method == http.MethodPut) && r.URL.Path == "/zones/z1/dns_records/r1":
		if m.failPatch {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":1004,"message":"kaputt"}],"messages":[],"result":null}`)
			return
		}
		var body struct {
			Content string `json:"content"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.content = body.Content
		m.patches++
		fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"r1","type":"A","name":"home.example.com","content":%q,"proxied":false,"ttl":60}}`, m.content)
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"success":false,"errors":[{"code":7003,"message":"unbekannt: %s %s"}],"messages":[],"result":null}`, r.Method, r.URL.Path)
	}
}

func (m *mockCF) stand() (string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.content, m.patches
}

// TestJederPushPrueftCloudflare: Eine gleiche IP wie beim letzten Push wird trotzdem gegen Cloudflare geprüft –
// Änderungen von außen und gescheiterte Updates heilen mit dem nächsten Push.
func TestJederPushPrueftCloudflare(t *testing.T) {
	m := &mockCF{content: "192.0.2.10"}
	srv := httptest.NewServer(m)
	defer srv.Close()

	api, err := cf.NewWithAPIToken("test", cf.BaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	u := NewUpdater(slog.Default(), "test_jeder_push")
	u.SetIPv4Zones("home.example.com")
	if err, _ := u.init(api); err != nil {
		t.Fatal(err)
	}
	u.StartWorker()
	st := u.actions[0].status

	push := func(ip string) {
		t.Helper()
		vorher := st.Last
		addr := net.ParseIP(ip)
		u.In <- &addr
		for ende := time.Now().Add(10 * time.Second); st.Last.Equal(vorher); {
			if time.Now().After(ende) {
				t.Fatalf("kein Durchlauf für %s", ip)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	pruefe := func(schritt, wantContent string, wantPatches int, wantOK, wantChanged bool) {
		t.Helper()
		content, patches := m.stand()
		if content != wantContent || patches != wantPatches || st.Succeeded != wantOK || st.Changed != wantChanged {
			t.Fatalf("%s: content=%s patches=%d succeeded=%v changed=%v, erwartet %s %d %v %v",
				schritt, content, patches, st.Succeeded, st.Changed, wantContent, wantPatches, wantOK, wantChanged)
		}
	}

	push("198.51.100.7")
	pruefe("neue IP", "198.51.100.7", 1, true, true)

	// Eintrag bei Cloudflare von außen geändert (Test vom 23.10.2026): gleicher Push muss korrigieren
	m.mu.Lock()
	m.content = "192.0.2.1"
	m.mu.Unlock()
	push("198.51.100.7")
	pruefe("gleiche IP nach Änderung von außen", "198.51.100.7", 2, true, true)

	// Nichts zu tun: kein Schreibzugriff, trotzdem erfolgreich
	push("198.51.100.7")
	pruefe("gleiche IP, Eintrag stimmt", "198.51.100.7", 2, true, false)

	// Gescheitertes Update wird als Fehler gemeldet …
	m.mu.Lock()
	m.content, m.failPatch = "192.0.2.1", true
	m.mu.Unlock()
	push("198.51.100.7")
	pruefe("Update scheitert", "192.0.2.1", 2, false, false)

	// … und mit dem nächsten Push gleicher IP nachgeholt
	m.mu.Lock()
	m.failPatch = false
	m.mu.Unlock()
	push("198.51.100.7")
	pruefe("Nachholen", "198.51.100.7", 3, true, true)
}

func (m *mockCF) setze(content string, failPatch bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.content, m.failPatch = content, failPatch
}

func warte(t *testing.T, was string, ok func() bool) {
	t.Helper()
	for ende := time.Now().Add(5 * time.Second); !ok(); {
		if time.Now().After(ende) {
			t.Fatalf("Zeitüberschreitung: %s", was)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestNachpruefung: Mit eingeschalteter Nachprüfung werden ein gescheitertes Update und eine Änderung von außen ohne
// neuen Push korrigiert; ohne vorherigen Push prüft sie nichts.
func TestNachpruefung(t *testing.T) {
	m := &mockCF{content: "192.0.2.10"}
	srv := httptest.NewServer(m)
	defer srv.Close()

	api, err := cf.NewWithAPIToken("test", cf.BaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	u := NewUpdater(slog.Default(), "test_nachpruefung")
	u.SetIPv4Zones("home.example.com")
	u.SetRecheckInterval(100 * time.Millisecond)
	if err, _ := u.init(api); err != nil {
		t.Fatal(err)
	}
	u.StartWorker()
	st := u.actions[0].status

	// ohne Push: keine Abfrage bei Cloudflare
	time.Sleep(350 * time.Millisecond)
	m.mu.Lock()
	lists := m.lists
	m.mu.Unlock()
	if lists != 0 {
		t.Fatal("Nachprüfung ohne vorherigen Push")
	}

	// Push, Update scheitert …
	m.setze("192.0.2.10", true)
	addr := net.ParseIP("198.51.100.7")
	u.In <- &addr
	warte(t, "Fehler gemeldet", func() bool { return !st.Last.IsZero() && !st.Succeeded })

	// … und wird ohne neuen Push nachgeholt
	m.setze("192.0.2.10", false)
	warte(t, "Nachholen", func() bool { c, _ := m.stand(); return c == "198.51.100.7" && st.Succeeded })
	if st.LastChange.IsZero() {
		t.Fatal("LastChange nicht gesetzt")
	}
	erste := st.LastChange

	// Änderung von außen wird zurückgesetzt
	m.setze("192.0.2.1", false)
	warte(t, "Änderung von außen korrigiert", func() bool { c, _ := m.stand(); return c == "198.51.100.7" })
	warte(t, "LastChange fortgeschrieben", func() bool { return st.LastChange.After(erste) })

	// stimmt alles, bleibt LastChange stehen und es wird nicht geschrieben
	_, p := m.stand()
	stand := st.LastChange
	time.Sleep(350 * time.Millisecond)
	if _, p2 := m.stand(); p2 != p || !st.LastChange.Equal(stand) {
		t.Fatalf("Nachprüfung schreibt ohne Abweichung: patches %d → %d", p, p2)
	}
}
