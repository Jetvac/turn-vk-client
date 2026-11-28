package split

import (
	"slices"
	"testing"
)

func TestIsRuApp(t *testing.T) {
	for _, p := range []string{"ru.oneme.app", "ru.rostel", "ru.sberbankmobile", "com.idamob.tinkoff.android",
		"ru.vtb24.mobilebanking.android", "ru.yandex.searchplugin", "com.yandex.browser", "com.wildberries.ru",
		"ru.ozon.app.android", "com.vk.vkvideo", "ru.vk.store", "ru.mail.mailapp"} {
		if !IsRuApp(p) {
			t.Errorf("%s: not Russian", p)
		}
	}
	for _, p := range []string{"org.telegram.messenger", "com.whatsapp", "com.google.android.youtube",
		"ru.zdevs.zarchiver", "io.github.jetvac.turnvk", "ru.yandexx", "com.vkx.app", ""} {
		if IsRuApp(p) {
			t.Errorf("%s: Russian", p)
		}
	}
}

// Russian apps stay out even where apps sent direct are let back in by a
// site through the VPN, and with split tunneling off; a rule of the user's
// sending one through the VPN wins.
func TestPlanRuApps(t *testing.T) {
	blocked := Rules{On: true, Default: Direct, Lists: []ListRule{{List: "geosite:ru-blocked", Route: VPN}},
		Apps: []AppRule{{Path: "ru.oneme.app", Route: Direct}, {Path: "ru.sberbankmobile", Route: VPN}, {Path: "org.telegram", Route: VPN}}}
	p := PlanApps(blocked)
	if p.Mode != "disallow" || len(p.Apps) != 0 || !p.Ru || !slices.Equal(p.RuIn, []string{"ru.sberbankmobile"}) {
		t.Fatalf("blocked through the VPN: %+v", p)
	}
	if p := PlanApps(Rules{Apps: blocked.Apps}); !p.Ru || len(p.RuIn) != 0 {
		t.Fatalf("split tunneling off: %+v", p)
	}
	blocked.RuVPN = true
	if p := PlanApps(blocked); p.Ru || len(p.RuIn) != 0 {
		t.Fatalf("Russian apps as the others: %+v", p)
	}
	if p := PlanApps(Rules{On: true, AppsOnly: true, Default: Direct}); p.Mode != "allow" || p.Ru {
		t.Fatalf("only chosen apps: %+v", p)
	}
}

func TestExplainRuApp(t *testing.T) {
	r := Rules{On: true, Default: VPN, Apps: []AppRule{{Path: "ru.sberbankmobile", Route: VPN}}}
	for _, c := range []struct {
		app  string
		ru   bool
		want Route
	}{
		{"ru.oneme.app", false, Direct},
		{"ru.oneme.app", true, VPN},
		{"ru.sberbankmobile", false, VPN}, // the user's own rule
		{"org.telegram", false, VPN},
		{`C:\ru.yandex.x\a.exe`, false, VPN},
	} {
		r.RuVPN = c.ru
		e, err := Explain(r, nil, "ifconfig.me", c.app, nil)
		if err != nil || e.Route != c.want {
			t.Errorf("%s (ruVpn %v): %+v %v", c.app, c.ru, e, err)
		}
	}
}
