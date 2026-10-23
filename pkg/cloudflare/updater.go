package cloudflare

import (
	"context"
	"fmt"
	cf "github.com/cloudflare/cloudflare-go"
	"github.com/cromefire/fritzbox-cloudflare-dyndns/pkg/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/net/publicsuffix"
	"log/slog"
	"net"
	"strings"
	"time"
)

type Action struct {
	DnsRecord string
	CfZoneId  string
	IpVersion uint8

	updates prometheus.Summary
	changes prometheus.Counter
	status  *util.UpdateStatus
}

type Updater struct {
	ipv4Zones []string
	ipv6Zones []string

	actions []*Action

	isInit bool
	api    *cf.API
	log    *slog.Logger

	In chan *net.IP

	// reqs: Abgleich mit Rückmeldung für den Push-Server (Apply), läuft im selben Worker wie In und die Nachprüfung
	reqs chan applyRequest


	subsystem string

	// recheck: Abstand der Nachprüfung mit der zuletzt gepushten IP (0 = aus; benji2k2-Fork)
	recheck time.Duration
}

func NewUpdater(log *slog.Logger, subsystem string) *Updater {
	return &Updater{
		isInit:    false,
		In:        make(chan *net.IP, 10),
		reqs:      make(chan applyRequest, 10),
		log:       log.With(slog.String("module", "cloudflare")),
		ipv4Zones: make([]string, 0),
		ipv6Zones: make([]string, 0),
		subsystem: subsystem,
	}
}

func (u Updater) makeSummary(labels prometheus.Labels) prometheus.Summary {
	return promauto.NewSummary(prometheus.SummaryOpts{
		Subsystem:   util.MakePromSubsystem(u.subsystem),
		Name:        "update_seconds",
		Help:        "A summary of the push server executions",
		Objectives:  map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		ConstLabels: labels,
	})
}

func (u Updater) makeCounter(labels prometheus.Labels) prometheus.Counter {
	return promauto.NewCounter(prometheus.CounterOpts{
		Subsystem:   util.MakePromSubsystem(u.subsystem),
		Name:        "changes_total",
		Help:        "Tatsächliche Änderungen (oder Neuanlagen) des Eintrags bei Cloudflare",
		ConstLabels: labels,
	})
}

// SetRecheckInterval schaltet die Nachprüfung ein: Im Abstand d werden die Einträge mit der zuletzt gepushten IP
// abgeglichen (gescheiterte Updates und Änderungen von außen werden so ohne neuen Push korrigiert).
func (u *Updater) SetRecheckInterval(d time.Duration) {
	u.recheck = d
}

type applyRequest struct {
	ip   *net.IP
	done chan bool
}

// Enabled: Cloudflare-Updates sind eingerichtet (Token und Zonen vorhanden).
func (u *Updater) Enabled() bool {
	return u.isInit
}

// Apply gleicht ip sofort ab und wartet auf das Ergebnis: ok = alle passenden Einträge stimmen jetzt (geändert oder
// schon richtig). timedOut, wenn der Abgleich nicht binnen wait fertig wurde – er läuft dann im Hintergrund weiter.
func (u *Updater) Apply(ip *net.IP, wait time.Duration) (ok bool, timedOut bool) {
	done := make(chan bool, 1)
	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case u.reqs <- applyRequest{ip: ip, done: done}:
	case <-timer.C:
		return false, true
	}

	select {
	case ok = <-done:
		return ok, false
	case <-timer.C:
		return false, true
	}
}

func (u *Updater) SetIPv4Zones(zones string) {
	u.ipv4Zones = strings.Split(zones, ",")
}

func (u *Updater) SetIPv6Zones(zones string) {
	u.ipv6Zones = strings.Split(zones, ",")
}

func (u *Updater) InitWithToken(token string) (error, []*util.UpdateStatus) {
	api, err := cf.NewWithAPIToken(token)

	if err != nil {
		return err, nil
	}

	return u.init(api)
}

func (u *Updater) InitWithKey(email string, key string) (error, []*util.UpdateStatus) {
	api, err := cf.New(key, email)

	if err != nil {
		return err, nil
	}

	return u.init(api)
}

func (u *Updater) init(api *cf.API) (error, []*util.UpdateStatus) {
	// Create unique list of zones and fetch their Cloudflare zone IDs
	zoneIdMap := make(map[string]string)

	for _, val := range u.ipv4Zones {
		zoneIdMap[val] = ""
	}

	for _, val := range u.ipv6Zones {
		zoneIdMap[val] = ""
	}

	for val := range zoneIdMap {
		zone, err := publicsuffix.EffectiveTLDPlusOne(val)

		if err != nil {
			return err, nil
		}

		id, err := api.ZoneIDByName(zone)

		if err != nil {
			return err, nil
		}

		zoneIdMap[val] = id
	}

	statusVec := []*util.UpdateStatus{}

	// Now create an updater action list
	for _, val := range u.ipv4Zones {
		zoneId := zoneIdMap[val]
		labels := prometheus.Labels{"record": val, "ip_version": "4"}
		updates := u.makeSummary(labels)
		status := util.UpdateStatus{Domain: val, IpVersion: 4, Succeeded: true}
		statusVec = append(statusVec, &status)

		a := &Action{
			DnsRecord: val,
			CfZoneId:  zoneId,
			IpVersion: 4,
			updates:   updates,
			changes:   u.makeCounter(labels),
			status:    &status,
		}

		u.actions = append(u.actions, a)
	}

	for _, val := range u.ipv6Zones {
		zoneId := zoneIdMap[val]
		labels := prometheus.Labels{"record": val, "ip_version": "6"}
		updates := u.makeSummary(labels)
		status := util.UpdateStatus{Domain: val, IpVersion: 4, Succeeded: true}
		statusVec = append(statusVec, &status)

		a := &Action{
			DnsRecord: val,
			CfZoneId:  zoneId,
			IpVersion: 6,
			updates:   updates,
			changes:   u.makeCounter(labels),
			status:    &status,
		}

		u.actions = append(u.actions, a)
	}

	u.api = api
	u.isInit = true

	return nil, statusVec
}

func (u *Updater) StartWorker() {
	if !u.isInit {
		return
	}

	go u.spawnWorker()
}

func (u *Updater) spawnWorker() {
	// Bewusst kein Vergleich mit der zuletzt gesetzten IP: Jeder Push liest die Einträge bei Cloudflare und ändert nur
	// abweichende. Die zuletzt gepushte IP dient nur der Nachprüfung, sie verhindert nie ein Update (benji2k2-Fork).
	var lastV4, lastV6 *net.IP
	// sofort merken – auch wenn das Update gleich scheitert, holt die Nachprüfung es nach
	remember := func(ip *net.IP) {
		if ip.To4() == nil {
			lastV6 = ip
		} else {
			lastV4 = ip
		}
	}

	var tick <-chan time.Time
	if u.recheck > 0 {
		ticker := time.NewTicker(u.recheck)
		defer ticker.Stop()
		tick = ticker.C
		u.log.Info("Recheck enabled", slog.Duration("interval", u.recheck))
	}

	for {
		select {
		case ip := <-u.In:
			remember(ip)
			u.log.Info("Received update request", slog.Any("ip", ip))
			u.runAll(ip, false)
		case r := <-u.reqs:
			remember(r.ip)
			u.log.Info("Received update request", slog.Any("ip", r.ip))
			r.done <- u.runAll(r.ip, false)
		case <-tick:
			if lastV4 != nil {
				u.runAll(lastV4, true)
			}
			if lastV6 != nil {
				u.runAll(lastV6, true)
			}
		}
	}
}

// runAll gleicht alle Einträge der passenden IP-Version ab; true, wenn alle danach stimmen.
func (u *Updater) runAll(ip *net.IP, recheck bool) bool {
	ok := true
	for _, action := range u.actions {
		// Nur Aktionen der passenden IP-Version
		if (ip.To4() == nil) != (action.IpVersion == 6) {
			continue
		}
		if !u.runAction(action, ip, recheck) {
			ok = false
		}
	}
	return ok
}

// runAction gleicht einen Eintrag mit der IP ab. Status und Dauer werden nur bei vollem Erfolg als erfolgreich
// gemeldet; Changed sagt, ob tatsächlich etwas geändert oder angelegt wurde. Bei der Nachprüfung (recheck) wird nur
// bei Änderung oder Fehler geloggt, und die Dauer-Metrik zählt weiter nur Durchläufe nach einem Push.
func (u *Updater) runAction(action *Action, ip *net.IP, recheck bool) bool {
	timer := prometheus.NewTimer(action.updates)

	// Create detailed sub-logger for this action
	alog := u.log.With(slog.String("domain", fmt.Sprintf("%s/IPv%d", action.DnsRecord, action.IpVersion)))
	if recheck {
		alog = alog.With(slog.Bool("recheck", true))
	}

	recordType := "A"
	if ip.To4() == nil {
		recordType = "AAAA"
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	fail := func(msg string, err error) {
		alog.Error(msg, util.ErrorAttr(err))
		action.status.Last = time.Now()
		action.status.Succeeded = false
		action.status.Changed = false
	}

	rc := cf.ZoneIdentifier(action.CfZoneId)

	// Research all current records matching the current scheme
	records, _, err := u.api.ListDNSRecords(ctx, rc, cf.ListDNSRecordsParams{
		Type: recordType,
		Name: action.DnsRecord,
	})
	if err != nil {
		fail("Action failed, could not research DNS records", err)
		return false
	}

	changed := false

	// Create record if none were found
	if len(records) == 0 {
		alog.Info("Creating DNS record")

		proxied := false

		_, err := u.api.CreateDNSRecord(ctx, rc, cf.CreateDNSRecordParams{
			Type:    recordType,
			Name:    action.DnsRecord,
			Content: ip.String(),
			Proxied: &proxied,
			TTL:     120,
		})
		if err != nil {
			fail("Action failed, could not create DNS record", err)
			return false
		}
		changed = true
	}

	// Update existing records
	for _, record := range records {
		if record.Content == ip.String() {
			if !recheck {
				alog.Info("DNS record already up to date", slog.Any("record-id", record.ID))
			}
			continue
		}

		alog.Info("Updating DNS record", slog.Any("record-id", record.ID), slog.String("old", record.Content))

		// Ensure we submit all required fields even if they did not change,otherwise
		// cloudflare-go might revert them to default values.
		_, err := u.api.UpdateDNSRecord(ctx, rc, cf.UpdateDNSRecordParams{
			ID:      record.ID,
			Content: ip.String(),
			TTL:     record.TTL,
			Proxied: record.Proxied,
		})
		if err != nil {
			fail("Action failed, could not update DNS record", err)
			return false
		}
		changed = true
	}

	now := time.Now()
	action.status.Last = now
	action.status.Succeeded = true
	action.status.Changed = changed
	if changed {
		action.status.LastChange = now
		action.changes.Inc()
	}

	if !recheck {
		timer.ObserveDuration()
	}
	return true
}
