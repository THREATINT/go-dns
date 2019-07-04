package Net

import "testing"

func TestLookupHostname(t *testing.T) {

	dnsClient := NewDNSClient("9.9.9.9")
	results, err := dnsClient.LookupHostname("dns.quad9.net")
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

	dnsClient := NewDNSClient("9.9.9.9")
	results, err := dnsClient.LookupAddr("9.9.9.9")
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
