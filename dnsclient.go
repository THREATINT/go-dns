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

	servers []string
	retries uint8
}

// NewClient (servers)
func NewClient(servers []string) *Client {
	client := Client{}
	client.client = &dns.Client{}

	if len(servers) == 0 {
		client.servers = []string{"127.0.0.1"}
	} else {
		client.servers = []string{}
		for _, dnsserver := range servers {
			client.servers = append(client.servers, net.JoinHostPort(dnsserver, "53"))
		}
	}

	return &client
}

// SetRetries (retries)
func (client *Client) SetRetries(retries uint8) {
	client.retries = retries
}

// Retries (client)
func (client *Client) Retries() uint8 {
	return client.retries
}

// SetTimeout (timeout)
func (client *Client) SetTimeout(timeout time.Duration) {
	client.client.Timeout = time.Second * timeout
}

// Timeout (client)
func (client *Client) Timeout() time.Duration {
	return client.client.Timeout
}

// randomDNSServer ()
func (client *Client) randomDNSServer() string {
	l := len(client.servers)
	if l == 1 {
		return client.servers[0]
	}

	return client.servers[rand.Intn(l)]
}

// LookupHostname (hostname)
func (client *Client) LookupHostname(hostname string) ([]string, error) {
	result := []string{}

	var retries uint8
	m := dns.Msg{}

retryA:
	m.SetQuestion(fmt.Sprintf("%s.", hostname), dns.TypeA)
	r, _, err := client.client.Exchange(&m, client.randomDNSServer())
	if err != nil {
		retries++

		if retries >= client.Retries() {
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
	r, _, err = client.client.Exchange(&m, client.randomDNSServer())
	if err != nil {
		retries++

		if retries >= client.Retries() {
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
func (client *Client) LookupAddr(addr string) ([]string, error) {
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
	r, _, err := client.client.Exchange(&m, client.randomDNSServer())
	if err != nil {
		retries++

		if retries >= client.Retries() {
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
