package dyndns

import (
	"github.com/cromefire/fritzbox-cloudflare-dyndns/pkg/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"log/slog"
	"net"
	"net/http"
	"time"
)

type Server struct {
	log            *slog.Logger
	out            chan<- *net.IP
	localIp        *net.IP
	pushExecutions prometheus.Summary
	status         *util.PushStatus

	Username string

	// Apply (benji2k2-Fork): gleicht die IP synchron ab; ist es gesetzt, antwortet der Push erst nach den Updates –
	// 200 nur, wenn alle Einträge stimmen, sonst 502 (Cloudflare-Fehler) bzw. 504 (nicht rechtzeitig fertig).
	// Ohne Apply wird die IP wie im Original nur an out übergeben.
	Apply func(ip *net.IP) (ok bool, timedOut bool)
	Password string
}

func NewServer(out chan<- *net.IP, localIp *net.IP, log *slog.Logger, subsystem string, status *util.PushStatus) *Server {
	pushExecutions := promauto.NewSummary(prometheus.SummaryOpts{
		Subsystem:  util.MakePromSubsystem(subsystem),
		Name:       "execution_seconds",
		Help:       "A summary of the push server executions",
		Objectives: map[float64]float64{0: 0, 0.5: 0.05, 0.9: 0.01, 0.99: 0.001, 1: 1},
	})
	return &Server{
		log:            log.With(slog.String("module", "dyndns")),
		out:            out,
		localIp:        localIp,
		pushExecutions: pushExecutions,
		status:         status,
	}
}

// forward gibt die IP weiter und liefert den Statuscode für die Antwort (200, 502 oder 504).
func (s *Server) forward(ip *net.IP) int {
	if s.Apply == nil {
		s.out <- ip
		return http.StatusOK
	}
	ok, timedOut := s.Apply(ip)
	switch {
	case timedOut:
		s.log.Warn("Cloudflare update not finished in time", slog.Any("ip", ip))
		return http.StatusGatewayTimeout
	case !ok:
		s.log.Warn("Cloudflare update failed", slog.Any("ip", ip))
		return http.StatusBadGateway
	}
	return http.StatusOK
}

// worse: schlechterer Statuscode für die Antwort (504 vor 502 vor 200)
func worse(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Handler offers a simple HTTP handler func for an HTTP server.
// It expects the IP address parameters and will relay them towards the Cloudflare updater
// worker once they get submitted.
//
// Expected parameters can be
//
//	"v4" IPv4 address
//	"v6" IPv6 address
//	"prefix" IPv6 prefix
//
// see https://service.avm.de/help/de/FRITZ-Box-Fon-WLAN-7490/016/hilfe_dyndns
func (s *Server) Handler(w http.ResponseWriter, r *http.Request) {
	s.status.Last = time.Now()
	timer := prometheus.NewTimer(s.pushExecutions)
	defer func() {
		timer.ObserveDuration()
	}()
	success := true
	code := http.StatusOK
	params := r.URL.Query()

	defer func() {
		s.status.Succeeded = success
	}()

	s.log.Info("Received incoming DynDNS update")

	if params.Get("username") != s.Username {
		s.log.Warn("Rejected due to username mismatch")
		success = false
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if params.Get("password") != s.Password {
		s.log.Warn("Rejected due to password mismatch")
		success = false
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Parse IPv4
	v4Str := params.Get("v4")
	if v4Str == "" {
		s.log.Warn("No IPv4 can be set as the `v4` parameter was not supplied")
	} else {
		ipv4 := net.ParseIP(v4Str)
		if ipv4 != nil && ipv4.To4() != nil {
			s.log.Info("Forwarding update request for IPv4", slog.Any("ipv4", ipv4))
			code = worse(code, s.forward(&ipv4))
		} else {
			s.log.Warn("Failed to parse IPv4 address", slog.String("input", v4Str))
			success = false
		}
	}

	if *s.localIp == nil {
		// Parse IPv6
		v6Str := params.Get("v6")
		if v6Str == "" {
			s.log.Warn("No IPv6 can be set as the `v6` parameter was not supplied")
		} else {
			ipv6 := net.ParseIP(v6Str)
			if ipv6 != nil && ipv6.To4() == nil {
				s.log.Info("Forwarding update request for IPv6", slog.Any("ipv6", ipv6))
				code = worse(code, s.forward(&ipv6))
			} else {
				s.log.Warn("Failed to parse IPv6 address", slog.String("input", v6Str))
				success = false
			}
		}
	} else {
		// Parse Prefix
		prefixStr := params.Get("prefix")
		if prefixStr == "" {
			s.log.Warn("No IPv6 can be calculated and set as the `prefix` parameter was not supplied")
		} else {
			_, prefix, err := net.ParseCIDR(prefixStr)
			if err != nil {
				s.log.Warn("Failed to parse prefix", slog.String("input", prefixStr), util.ErrorAttr(err))
				success = false
			} else {

				constructedIp := make(net.IP, net.IPv6len)
				copy(constructedIp, prefix.IP)

				maskLen, _ := prefix.Mask.Size()

				for i := 0; i < net.IPv6len; i++ {
					b := constructedIp[i]
					lb := (*s.localIp)[i]
					var mask byte = 0b00000000
					for j := 0; j < 8; j++ {
						if (i*8 + j) >= maskLen {
							mask += 0b00000001 << (7 - j)
						}
					}
					b += lb & mask
					constructedIp[i] = b
				}

				s.log.Info("Forwarding update request for IPv6", slog.Any("prefix", prefix), slog.Any("ipv6", constructedIp))
				code = worse(code, s.forward(&constructedIp))
			}
		}
	}

	if success {
		// 200 statt 202 (benji2k2-Fork): die FRITZ!Box meldet bei 202 „DynDNS-Fehler … Fehler 0“; mit Apply erst nach den
		// Updates und nur bei vollem Erfolg, sonst 502/504
		w.WriteHeader(code)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}
