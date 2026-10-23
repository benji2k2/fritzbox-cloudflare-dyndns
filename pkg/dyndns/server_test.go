package dyndns

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cromefire/fritzbox-cloudflare-dyndns/pkg/util"
)

// TestAntwortcodes (benji2k2-Fork): Mit Apply antwortet der Push erst nach dem Abgleich – 200 nur bei Erfolg.
func TestAntwortcodes(t *testing.T) {
	out := make(chan *net.IP, 10)
	var localIp net.IP
	status := util.PushStatus{Succeeded: true}
	s := NewServer(out, &localIp, slog.Default(), "test_antwortcodes", &status)
	s.Username, s.Password = "fritzbox", "probe"

	var ergebnis struct{ ok, timedOut bool }
	aufrufe := 0
	s.Apply = func(ip *net.IP) (bool, bool) {
		aufrufe++
		return ergebnis.ok, ergebnis.timedOut
	}

	push := func(query string) int {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Handler(rec, httptest.NewRequest(http.MethodGet, "/ip?"+query, nil))
		return rec.Code
	}
	gut := "v4=198.51.100.7&username=fritzbox&password=probe"

	ergebnis.ok, ergebnis.timedOut = true, false
	if c := push(gut); c != http.StatusOK || aufrufe != 1 {
		t.Fatalf("Erfolg: %d (Aufrufe %d), erwartet 200", c, aufrufe)
	}
	ergebnis.ok = false
	if c := push(gut); c != http.StatusBadGateway {
		t.Fatalf("Cloudflare-Fehler: %d, erwartet 502", c)
	}
	ergebnis.timedOut = true
	if c := push(gut); c != http.StatusGatewayTimeout {
		t.Fatalf("Zeitüberschreitung: %d, erwartet 504", c)
	}
	vorher := aufrufe
	if c := push("v4=198.51.100.7&username=fritzbox&password=falsch"); c != http.StatusUnauthorized || aufrufe != vorher {
		t.Fatalf("falsches Passwort: %d (Apply aufgerufen: %v), erwartet 401 ohne Apply", c, aufrufe != vorher)
	}
	if c := push("v4=kaputt&username=fritzbox&password=probe"); c != http.StatusBadRequest {
		t.Fatalf("ungültige IP: %d, erwartet 400", c)
	}

	// ohne Apply wie im Original: IP an out, sofort 200
	s.Apply = nil
	if c := push(gut); c != http.StatusOK || len(out) != 1 {
		t.Fatalf("ohne Apply: %d, out=%d", c, len(out))
	}
}
