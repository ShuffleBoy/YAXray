package i18n

import "testing"

func TestFirstAppleLanguage(t *testing.T) {
	out := "(\n    \"ru-RU\",\n    \"en-RU\"\n)\n"
	if got := firstAppleLanguage(out); got != "ru-RU" {
		t.Fatalf("got %q", got)
	}
}

func TestSetAndT(t *testing.T) {
	defer Set(EN)
	Set("ru_RU.UTF-8")
	if T("Connect", "Подключить") != "Подключить" || Lang() != RU {
		t.Fatal("expected Russian")
	}
	for _, l := range []string{"en-US", "de-DE", "", "C"} {
		Set(l)
		if T("Connect", "Подключить") != "Connect" {
			t.Fatalf("%q: expected English", l)
		}
	}
}
