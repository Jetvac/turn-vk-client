package split

import "strings"

// Russian apps out of the VPN (Rules.RuVPN off, the default): on Android
// MAX, Госуслуги, banks, marketplaces, Yandex, VK and other Russian apps
// do not enter the tunnel, whatever the mode, even with split tunneling
// off. Such apps check whether their own network is a VPN (MAX then
// refuses to send messages), ask IP-check services for their address and
// report both; inside the tunnel the foreign services among those would
// tell them the VPN's exit address. Out of it they see an ordinary
// network and the phone's own address. The user's own rule sending such
// an app through the VPN wins (while split tunneling is on).

// ruExact: Russian apps by package name.
var ruExact = map[string]bool{
	"ru.rostel":                      true, // Госуслуги
	"com.idamob.tinkoff.android":     true, // Т-Банк
	"com.uma.musicvk":                true, // VK Музыка
	"ru.kinopoisk":                   true,
	"ru.instamart":                   true, // Купер
	"ru.more.play":                   true, // Okko
	"com.kms.free":                   true, // Kaspersky
	"com.octopod.russianpost.client": true, // Почта России
}

// ruPrefixes: the namespaces of Russian makers' packages.
var ruPrefixes = []string{
	"ru.oneme.", // MAX
	"com.vkontakte.", "com.vk.", "ru.vk.", "ru.ok.", "ru.mail.", "ru.zen.",
	"ru.yandex.", "com.yandex.", "ru.beru.", "ru.foodfox.",
	"ru.sberbank", "ru.sber.", "ru.vtb", "ru.alfabank.", "ru.tinkoff.", "ru.raiffeisen",
	"ru.gazprombank.", "ru.psbank.", "ru.nspk.",
	"ru.ozon.", "com.wildberries.", "com.avito.", "ru.auto.", "ru.cian.", "ru.hh.",
	"ru.mts.", "ru.megafon.", "ru.beeline.", "ru.tele2.", "ru.rt.",
	"ru.gosuslugi.", "ru.rzd.", "ru.dublgis.", "ru.rutube.", "ru.ivi.", "com.kaspersky.",
}

// IsRuApp tells whether an Android package is a Russian app kept out of
// the VPN.
func IsRuApp(pkg string) bool {
	if ruExact[pkg] {
		return true
	}
	for _, p := range ruPrefixes {
		if strings.HasPrefix(pkg, p) {
			return true
		}
	}
	return false
}

// ruOwnVPN: the user's own rule sends the app through the VPN.
func ruOwnVPN(r *Rules, pkg string) bool {
	if !r.On {
		return false
	}
	for _, a := range r.Apps {
		if !a.Off && !a.Folder && a.Route == VPN && a.Path == pkg {
			return true
		}
	}
	return false
}

// ruOut: the rules keep this Android package out of the tunnel as a
// Russian app.
func ruOut(r *Rules, pkg string) bool {
	return !r.RuVPN && !strings.ContainsAny(pkg, `\/`) && IsRuApp(pkg) && !ruOwnVPN(r, pkg)
}
