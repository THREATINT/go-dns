package dns

import "testing"

func TestLookupHostname(t *testing.T) {

	Client := NewClient([]string{"9.9.9.9"})
	results, err := Client.LookupHostname("dns.quad9.net")
	if err != nil {
		t.Error(err.Error())
	} else {
		if len(results) == 0 {
			t.Error("len(results)==0!")

		} else {
			t.Logf("%s", results)
		}
	}
}

func TestLookupAddr(t *testing.T) {

	Client := NewClient([]string{"9.9.9.9"})
	results, err := Client.LookupAddr("9.9.9.9")
	if err != nil {
		t.Error(err.Error())
	} else {
		if len(results) == 0 {
			t.Error("len(results)==0!")

		} else {
			t.Logf("%s", results)
		}
	}
}
