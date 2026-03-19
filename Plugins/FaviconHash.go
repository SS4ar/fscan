package Plugins

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/Common"
)

// Known favicon hashes (Shodan mmh3 format) mapped to product names.
// These are the most commonly encountered products in penetration testing.
var knownFavicons = map[int32]string{
	// Web servers & proxies
	116323821:  "Nginx default",
	-1137994595: "Apache Tomcat",
	-297069493: "Apache httpd",
	1485257654: "IIS default",
	-1293291467: "Caddy",

	// Network devices
	-305179312: "Fortinet FortiGate",
	945408572:  "Cisco WebVPN",
	-64644196:  "Cisco ASA",
	-1273514654: "Palo Alto Networks",
	735701051:  "Juniper Web Device Manager",
	-843667523: "MikroTik RouterOS",
	362091310:  "Ubiquiti UniFi",
	632926722:  "pfSense",
	-1015085762: "SonicWall",
	-1166125415: "F5 BIG-IP",

	// CMS
	-235701012: "WordPress",
	-1395852043: "Joomla",
	116562887:  "Drupal",
	-1721699022: "Confluence",
	985820992:  "MediaWiki",
	-244067125: "Ghost CMS",

	// DevOps / CI-CD
	-1607431042: "Jenkins",
	81586312:   "GitLab",
	-1032603498: "Gitea",
	-1249852504: "Grafana",
	-544941629: "Kibana",
	1485890173: "SonarQube",
	1782565349: "Nexus Repository",
	-1090132073: "Harbor",
	-1051801340: "Argo CD",

	// Databases
	-839860095: "phpMyAdmin",
	-268938890: "pgAdmin",
	-1502944387: "MongoDB Compass Web",
	-1200467970: "Elastic HQ",
	-1412425559: "Adminer",

	// Application frameworks
	-1960975584: "Spring Boot",
	116459498:  "Django",
	-58825023:  "Ruby on Rails",

	// Security tools
	-357937929: "Burp Suite",
	99395752:   "Nessus",
	-496735217: "OpenVAS",
	-1073467790: "Zabbix",
	-428095498: "Nagios",

	// Virtualization & cloud
	1960098605: "VMware ESXi",
	829576016:  "VMware vCenter",
	-1654963157: "Proxmox VE",
	-240938922: "oVirt / RHEV",

	// Mail & collaboration
	-1290013498: "Roundcube",
	-1102858400: "Zimbra",
	688839498:   "Outlook Web App",

	// Storage
	-1616143106: "Synology DSM",
	-1572303854: "QNAP QTS",
	-1103551459: "TrueNAS / FreeNAS",

	// Java middleware
	-475218614: "WebLogic",
	-1972016040: "JBoss / WildFly",
	988422585:  "GlassF,ish",

	// Chinese ecosystem (common in pentests)
	-1005928092: "Zhiyuan OA",
	1165838194: "Tongda OA",
	1695032093: "Seeyon OA",
	-1210588485: "Ruijie Network",
}

// mmh3Hash32 computes MurmurHash3 (32-bit) compatible with Shodan favicon search.
func mmh3Hash32(data []byte) int32 {
	// Base64 encode first (Shodan convention)
	b64 := base64.StdEncoding.EncodeToString(data)
	raw := []byte(b64)

	var h1 uint32 = 0
	const c1 uint32 = 0xcc9e2d51
	const c2 uint32 = 0x1b873593
	length := len(raw)
	nblocks := length / 4

	for i := 0; i < nblocks; i++ {
		k1 := uint32(raw[i*4]) | uint32(raw[i*4+1])<<8 | uint32(raw[i*4+2])<<16 | uint32(raw[i*4+3])<<24
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}

	tail := raw[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}

	h1 ^= uint32(length)
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16

	return int32(h1)
}

// FaviconScan fetches favicon.ico from a web server and computes fingerprint hashes.
// Returns product name if matched, or hash string for manual lookup.
func FaviconScan(url string) string {
	faviconURL := strings.TrimRight(url, "/") + "/favicon.ico"

	client := &http.Client{
		Timeout: time.Duration(Common.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Get(faviconURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	// Read favicon (limit to 1MB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil || len(body) == 0 {
		return ""
	}

	// Compute hashes
	mmh3 := mmh3Hash32(body)
	md5sum := fmt.Sprintf("%x", md5.Sum(body))

	// Check known favicon database
	if product, ok := knownFavicons[mmh3]; ok {
		return fmt.Sprintf("[Favicon] %s (mmh3:%d md5:%s)", product, mmh3, md5sum)
	}

	// Return hash for manual Shodan lookup: http.favicon.hash:<mmh3>
	return fmt.Sprintf("[Favicon] mmh3:%d md5:%s", mmh3, md5sum)
}
