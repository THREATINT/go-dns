package dns

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	TInet "github.com/THREATINT/go-net"
	"github.com/miekg/dns"
)

type DNSClient struct {
	client *dns.Client

	dnsServers []string
	retries    uint8
}

// NewDNSClient(dnsservers []string) *DNSClient
func NewDNSClient(dnsservers []string) *DNSClient {
	dnsclient := DNSClient{}
	dnsclient.client = &dns.Client{}

	if len(dnsservers) == 0 {
		dnsclient.dnsServers = []string{"127.0.0.1"}
	} else {
		dnsclient.dnsServers = []string{}
		for _, dnsserver := range dnsservers {
			dnsclient.dnsServers = append(dnsclient.dnsServers, net.JoinHostPort(dnsserver, "53"))
		}
	}

	return &dnsclient
}

// (dnsclient *DNSClient) SetRetries(retries uint8)
func (dnsclient *DNSClient) SetRetries(retries uint8) {
	dnsclient.retries = retries
}

// (dnsclient *DNSClient) Retries() uint8
func (dnsclient *DNSClient) Retries() uint8 {
	return dnsclient.retries
}

// (dnsclient *DNSClient) SetTimeout(timeout time.Duration)
func (dnsclient *DNSClient) SetTimeout(timeout time.Duration) {
	dnsclient.client.Timeout = time.Second * timeout
}

// (dnsclient *DNSClient) Timeout() time.Duration
func (dnsclient *DNSClient) Timeout() time.Duration {
	return dnsclient.client.Timeout
}

// (dnsclient *DNSClient) randomDNSServer() string
func (dnsclient *DNSClient) randomDNSServer() string {
	l := len(dnsclient.dnsServers)
	if l == 1 {
		return dnsclient.dnsServers[0]
	} else {
		return dnsclient.dnsServers[rand.Intn(l)]
	}
}

// (dnsclient *DNSClient) LookupHostname(hostname string) ([]string, error)
func (dnsclient *DNSClient) LookupHostname(hostname string) ([]string, error) {
	result := []string{}

	var retries uint8
	m := dns.Msg{}

retryA:
	m.SetQuestion(fmt.Sprintf("%s.", hostname), dns.TypeA)
	r, _, err := dnsclient.client.Exchange(&m, dnsclient.randomDNSServer())
	if err != nil {
		retries++

		if retries >= dnsclient.Retries() {
			return result, err
		}

		goto retryA
	}
	for _, answ := range r.Answer {
		switch answ.(type) {
		case *dns.CNAME:
			result = append(result, (answ.(*dns.CNAME)).Target)

		case *dns.A:
			result = append(result, ((answ.(*dns.A)).A).String())
		}
	}

	retries = 0
	m.SetQuestion(fmt.Sprintf("%s.", hostname), dns.TypeAAAA)

retryAAAA:
	r, _, err = dnsclient.client.Exchange(&m, dnsclient.randomDNSServer())
	if err != nil {
		retries++

		if retries >= dnsclient.Retries() {
			return result, err
		}

		goto retryAAAA
	}
	for _, answ := range r.Answer {
		switch answ.(type) {
		case *dns.CNAME:
			result = append(result, (answ.(*dns.CNAME)).Target)

		case *dns.AAAA:
			result = append(result, ((answ.(*dns.AAAA)).AAAA).String())
		}
	}

	return result, nil
}

// (dnsclient *DNSClient) LookupAddr(addr string) ([]string, error)
func (dnsclient *DNSClient) LookupAddr(addr string) ([]string, error) {
	result := []string{}

	ipaddr := net.ParseIP(addr)

	if TInet.IsIPv4(ipaddr) {
		ipaddr = ipaddr.To4()
	} else {
		ipaddr = ipaddr.To16()
	}

	a := "in-addr.arpa."
	for i := 0; i < len(ipaddr); i++ {
		a = fmt.Sprintf("%v.%s", ipaddr[i], a)
	}

	var retries uint8
	m := dns.Msg{}
	m.SetQuestion(a, dns.TypePTR)

retry:
	r, _, err := dnsclient.client.Exchange(&m, dnsclient.randomDNSServer())
	if err != nil {
		retries++

		if retries >= dnsclient.Retries() {
			return result, err
		}

		goto retry

	}
	for _, answ := range r.Answer {
		switch answ.(type) {
		case *dns.PTR:
			result = append(result, strings.TrimRight((answ.(*dns.PTR)).Ptr, "."))

		case *dns.CNAME:
			result = append(result, strings.TrimRight((answ.(*dns.CNAME)).Target, "."))
		}
	}

	return result, nil
}
