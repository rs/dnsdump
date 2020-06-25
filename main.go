package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

func main() {
	b, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil {
		panic(err)
	}

	printHeader(h)
	printQuestionSection(&p)
	printResourceSection("ANSWER", p.Answer)
	printResourceSection("AUTHORITY", p.Authority)
	printResourceSection("ADDITIONAL", p.Additional)
}

func printHeader(h dnsmessage.Header) {
	fmt.Printf(";; opcode: %s, status: %s, id: %d\n", opcode(h.OpCode), rcode(h.RCode), h.ID)
	fmt.Printf(";; flags: %s\n", strings.Join(flags(h), " "))
	fmt.Println()
}

func printQuestionSection(p *dnsmessage.Parser) {
	fmt.Println(";; QUESTION SECTION:")
	for {
		q, err := p.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			panic(err)
		}
		fmt.Printf(";%s\t\t%s\t%s\n", q.Name.String(), class(q.Class), typ(q.Type))
	}
	fmt.Println()
}

func printResourceSection(name string, f func() (dnsmessage.Resource, error)) {
	var present bool
	var opts []dnsmessage.Resource
	for {
		r, err := f()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			panic(err)
		}
		hdr := r.Header
		if hdr.Type == dnsmessage.TypeOPT {
			opts = append(opts, r)
			continue
		}
		if !present {
			present = true
			fmt.Printf(";; %s SECTION:\n", name)
		}
		fmt.Printf("%s\t%d\t%s\t%s\t%s\n", hdr.Name.String(), hdr.TTL, class(hdr.Class), typ(hdr.Type), body(r.Body))

	}
	if present {
		fmt.Println()
	}

	if len(opts) > 0 {
		for _, r := range opts {
			hdr := r.Header
			fmt.Println(";; EDNS PSEUDOSECTION:")
			fmt.Printf(";; Version: %d, ext-rcode: %d; udp size: %d\n", hdr.TTL&0xf, hdr.TTL>>8, hdr.Class)
			for _, opt := range (r.Body.(*dnsmessage.OPTResource)).Options {
				fmt.Printf(";; %s\n", ednsdata(opt))
			}
		}
	}
}

func body(b dnsmessage.ResourceBody) string {
	switch b := b.(type) {
	case *dnsmessage.AResource:
		return net.IP(b.A[:]).String()
	case *dnsmessage.NSResource:
		return b.NS.String()
	case *dnsmessage.CNAMEResource:
		return b.CNAME.String()
	case *dnsmessage.SOAResource:
		return fmt.Sprintf("%s %s %d %d %d %d %d", b.NS, b.MBox, b.Serial, b.Refresh, b.Retry, b.Expire, b.MinTTL)
	case *dnsmessage.PTRResource:
		return b.PTR.String()
	case *dnsmessage.MXResource:
		return fmt.Sprintf("%d %s", b.Pref, b.MX)
	case *dnsmessage.TXTResource:
		return strings.Join(b.TXT, " ")
	case *dnsmessage.AAAAResource:
		return net.IP(b.AAAA[:]).String()
	case *dnsmessage.SRVResource:
		return fmt.Sprintf("%d %d %d %s", b.Priority, b.Weight, b.Port, b.Target.String())
	default:
		return b.GoString()
	}
}

func opcode(op dnsmessage.OpCode) string {
	switch op {
	case 0:
		return "QUERY"
	case 1:
		return "IQUERY"
	case 2:
		return "STATUS"
	default:
		return fmt.Sprint(op)
	}
}

func rcode(rc dnsmessage.RCode) string {
	switch rc {
	case dnsmessage.RCodeSuccess:
		return "SUCCESS"
	case dnsmessage.RCodeFormatError:
		return "FORMAT_ERROR"
	case dnsmessage.RCodeServerFailure:
		return "SERVER_FAILURE"
	case dnsmessage.RCodeNameError:
		return "NAME_ERROR"
	case dnsmessage.RCodeNotImplemented:
		return "NOT_IMPLEMENTED"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	default:
		return rc.String()
	}
}

func ednsdata(opt dnsmessage.Option) string {
	switch opt.Code {
	case 0x1: // long lived queries: http://tools.ietf.org/html/draft-sekar-dns-llq-01
		return "LLQ"
	case 0x2: // update lease draft: http://files.dns-sd.org/draft-sekar-dns-ul.txt
		return "UL"
	case 0x3: // nsid (See RFC 5001)
		return fmt.Sprintf("NSID: %x", opt.Data)
	case 0x5: // DNSSEC Algorithm Understood
		return "DAU"
	case 0x6: // DS Hash Understood
		return "DHU"
	case 0x7: // NSEC3 Hash Understood
		return "N3U"
	case 0x8: // client-subnet (See RFC 7871)
		if len(opt.Data) < 8 {
			return "SUBNET (invalid)"
		}
		source := opt.Data[2]
		scope := opt.Data[3]
		ip := net.IP(opt.Data[4:])
		return fmt.Sprintf("SUBNET: %s/%d/%d", ip, source, scope)
	case 0x9: // EDNS0 expire
		var expire uint32
		if len(opt.Data) == 4 {
			expire = uint32(opt.Data[0])<<24 | uint32(opt.Data[1])<<16 | uint32(opt.Data[2])<<8 | uint32(opt.Data[3])
		}
		return fmt.Sprintf("EXPIRE: %dms", expire)
	case 0xa: // EDNS0 Cookie
		var client []byte
		var server []byte
		if len(opt.Data) >= 8 {
			client = opt.Data[:8]
			server = opt.Data[8:]
		}
		return fmt.Sprintf("COOKIE: %x %x", client, server)
	case 0xb: // EDNS0 tcp keep alive (See RFC 7828)
		var timeout uint8
		if len(opt.Data) == 1 {
			timeout = opt.Data[0]
		}
		return fmt.Sprintf("TCPKEEPALIVE: %dms", timeout*100)
	case 0xc: // EDNS0 padding (See RFC 7830)
		return fmt.Sprintf("PADDING: %d B", len(opt.Data))
	case 0xFDE9: // Beginning of range reserved for local/experimental use (See RFC 6891)
		return "LOCALSTART"
	case 0xFFFE: // End of range reserved for local/experimental use (See RFC 6891)
		return "LOCALEND"
	default:
		return fmt.Sprintf("%d\t %v", opt.Code, opt.Data)
	}
}

func flags(h dnsmessage.Header) []string {
	f := []string{}
	if h.Authoritative {
		f = append(f, "aa")
	}
	if h.Truncated {
		f = append(f, "tr")
	}
	if h.RecursionDesired {
		f = append(f, "rd")
	}
	if h.RecursionAvailable {
		f = append(f, "ra")
	}
	return f
}

func class(c dnsmessage.Class) string {
	switch c {
	case dnsmessage.ClassINET:
		return "IN"
	case dnsmessage.ClassCSNET:
		return "CS"
	case dnsmessage.ClassCHAOS:
		return "CH"
	case dnsmessage.ClassHESIOD:
		return "HESIOD"
	case dnsmessage.ClassANY:
		return "ANY"
	}
	return "?"
}

func typ(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeSOA:
		return "SOA"
	case dnsmessage.TypePTR:
		return "PTR"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeSRV:
		return "SRV"
	case dnsmessage.TypeOPT:
		return "OPT"
	case dnsmessage.TypeWKS:
		return "WKS"
	case dnsmessage.TypeHINFO:
		return "HINFO"
	case dnsmessage.TypeMINFO:
		return "MINFO"
	case dnsmessage.TypeAXFR:
		return "AXFR"
	case dnsmessage.TypeALL:
		return "ALL"
	default:
		return fmt.Sprintf("%d", t)
	}
}
