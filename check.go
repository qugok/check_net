package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	nmap "github.com/Ullaakut/nmap/v2"
	opts "github.com/jpillora/opts"
	ping "github.com/prometheus-community/pro-bing"
	probing "github.com/prometheus-community/pro-bing"
	yaml "gopkg.in/yaml.v2"
)

type nmapCheck struct {
	Url        string `yaml:"url"`
	Port       string `yaml:"port"`
	Udp        bool   `yaml:"udp"`
	TimeoutSec int    `yaml:"timeout_sec"`
}

type pingCheck struct {
	Url   string `yaml:"url"`
	Count int    `yaml:"count"`
}

type dnsCheck struct {
	DnsServers    []string `yaml:"dns_servers"`
	DnsTimeoutSec int      `yaml:"dns_timout_sec"`
	UrlsToCheck   []string `yaml:"urls_to_check"`
}

type Config struct {
	NsLookupCheck dnsCheck    `yaml:"nslookup_check"`
	NmapChecks    []nmapCheck `yaml:"nmap_checks"`
	PingChecks    []pingCheck `yaml:"ping_checks"`
}

func checkResolving(conf dnsCheck) bool {
	for _, dns := range conf.DnsServers {
		urlResulrts := LookupHosts(
			dns,
			conf.UrlsToCheck,
			true,
			time.Duration(conf.DnsTimeoutSec)*time.Second,
		)
		for _, res := range urlResulrts {
			if len(res.ips) != 0 {
				fmt.Println("successful resolved", dns, res.url, res.ips)
				return true
			}
		}
	}
	fmt.Println("resolving failed")
	return false
}

type result struct {
	url string
	ips []string
}

func LookupHosts(dns string, urls []string, exitAfterSuccess bool, dnsTimeout time.Duration) []result {
	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout:   dnsTimeout, // example timeout
				LocalAddr: nil,        // bind address to use (e.g., local IP)
			}
			return dialer.DialContext(ctx, network, dns)
		},
	}
	ans := make([]result, 0, len(urls))
	for _, url := range urls {
		// fmt.Println("processing url", url, "with dns", dns)
		addrs, _ := resolver.LookupHost(context.Background(), url)
		ans = append(ans, result{url: url, ips: addrs})
		if exitAfterSuccess && len(addrs) != 0 {
			return ans[len(ans)-1:]
		}
	}
	return ans
}

func checkNmap(conf Config) {
	for _, check := range conf.NmapChecks {
		scanResult := scanPortWithTimeout(time.Duration(check.TimeoutSec)*time.Second, check.Udp, check.Url, check.Port)
		p := "tcp"
		if check.Udp {
			p = "udp"
		}
		if scanResult.available {
			fmt.Println("ok scan", p, check.Url, check.Port, "latency:", scanResult.latency, "sec")
		} else {
			fmt.Println("fail scan", p, check.Url, check.Port)
		}
	}
}

type scanReport struct {
	available bool
	latency   float32
}

func scanPortWithTimeout(timeout time.Duration, udp bool, addr, port string) scanReport {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return scanPort(ctx, udp, addr, port)
}
func scanPort(ctx context.Context, udp bool, addr, port string) scanReport {
	options := []nmap.Option{
		nmap.WithUDPScan(),
		nmap.WithTargets(addr),
		nmap.WithPorts(port),
		nmap.WithContext(ctx),
	}
	if udp {
		options = options[1:]
	}
	scanner, err := nmap.NewScanner(options...)

	if err != nil {
		fmt.Printf("unable to create nmap scanner: %v\n", err)
		return scanReport{}
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		fmt.Printf("unable to run nmap scan: %v\n", err)
		if warnings != nil {
			fmt.Printf("Warnings: \n %v\n", warnings)
		}
		return scanReport{available: false}
	}

	if warnings != nil {
		fmt.Printf("Warnings: \n %v\n", warnings)
	}

	if len(result.Hosts) == 0 {
		return scanReport{available: false}
	}

	return scanReport{available: true, latency: result.Stats.Finished.Elapsed}
}

func checkPing(conf Config) {
	for _, pingConf := range conf.PingChecks {
		RunPing(pingConf)
	}
}

func RunPing(conf pingCheck) {
	pinger, err := ping.NewPinger(conf.Url)
	if err != nil {
		fmt.Println(err)
		return
	}
	pinger.Count = conf.Count
	fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())

	pinger.OnRecv = func(pkt *probing.Packet) {
		fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
	}

	pinger.OnDuplicateRecv = func(pkt *probing.Packet) {
		fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v ttl=%v (DUP!)\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.TTL)
	}

	pinger.OnFinish = func(stats *probing.Statistics) {
		fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
		fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
		fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n\n",
			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
	}

	err = pinger.Run() // Blocks until finished.
	if err != nil {
		panic(err)
	}
}

var defaultConfig = Config{
	NsLookupCheck: dnsCheck{
		DnsServers: []string{
			"8.8.8.8:53",
			"8.8.4.4:53",
			"77.88.8.8:53",
			"77.88.8.1:53",
		},
		DnsTimeoutSec: 10,
		UrlsToCheck:   []string{"www.rbc.ru", "www.news.ru"},
	},
	NmapChecks: []nmapCheck{
		{Url: "178.248.234.119", Port: "53", Udp: true, TimeoutSec: 10},
		{Url: "178.248.234.119", Port: "443", TimeoutSec: 10},
		{Url: "178.248.234.119", Port: "80", TimeoutSec: 10},
		{Url: "www.rbc.ru", Port: "80", TimeoutSec: 10},
	},
	PingChecks: []pingCheck{
		{Url: "178.248.234.119", Count: 4},
		{Url: "www.rbc.ru", Count: 4},
	},
}

func main() {
	type config struct {
		File        string `opts:"help=config file path,mode=arg"`
		PrintConfig bool   `opts:"help=print default config to config file"`
	}
	c := config{}
	opts.Parse(&c)

	if c.PrintConfig {
		out, err := yaml.Marshal(defaultConfig)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = os.WriteFile(c.File, out, 0666)
		if err != nil {
			fmt.Println(err)
			return
		}
		return
	}

	var conf Config
	out, err := os.ReadFile(c.File)
	if err != nil {
		fmt.Printf("faled to read config: %v\n", err)
		return
	}
	err = yaml.Unmarshal(out, &conf)
	if err != nil {
		fmt.Printf("failed to parse config: %v\n", err)
		return
	}

	checkResolving(conf.NsLookupCheck)

	fmt.Println()
	fmt.Println("Start scannig by nmap\n")
	checkNmap(conf)

	fmt.Println()
	fmt.Println("Start scannig with ping\n")
	checkPing(conf)
}
