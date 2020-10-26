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

// Client struct
type Client struct {
	client *dns.Client

	dnsServers []string
	retries    uint8
}

// NewDNSClient (dnsservers)
func NewClient(dnsservers []string) *Client {
	dnsclient := Client{}
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

// SetRetries (retries)
func (dnsclient *Client) SetRetries(retries uint8) {
	dnsclient.retries = retries
}

// Retries
func (dnsclient *Client) Retries() uint8 {
	return dnsclient.retries
}

// SetTimeout (timeout)
func (dnsclient *Client) SetTimeout(timeout time.Duration) {
	dnsclient.client.Timeout = time.Second * timeout
}

// Timeout
func (dnsclient *Client) Timeout() time.Duration {
	return dnsclient.client.Timeout
}

// randomDNSServer ()
func (dnsclient *Client) randomDNSServer() string {
	l := len(dnsclient.dnsServers)
	if l == 1 {
		return dnsclient.dnsServers[0]
	}

	return dnsclient.dnsServers[rand.Intn(l)]
}

// LookupHostname (hostname)
func (dnsclient *Client) LookupHostname(hostname string) ([]string, error) {
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

// LookupAddr (addr)
func (dnsclient *Client) LookupAddr(addr string) ([]string, error) {
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
