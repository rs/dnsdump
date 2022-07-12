# DNS Packet Dump

dnsdump is parses DNS packet in binary format, and output it in a dig-like
format.

Examples:

```
> echo AAABAAABAAAAAAABE3A2MS1rZXl2YWx1ZXNlcnZpY2UGaWNsb3VkA2NvbQAAHAABAAApAgAAAAAAAEUADABBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA | base64 -D | dnsdump
;; opcode: QUERY, status: SUCCESS, id: 0
;; flags: rd

;; QUESTION SECTION:
;p61-keyvalueservice.icloud.com.		IN	AAAA

;; EDNS PSEUDOSECTION:
;; Version: 0, ext-rcode: 0; udp size: 512
;; PADDING: 65 B
```

```
> curl -s 'https://dns.nextdns.io?dns=AAABAAABAAAAAAABE3A2MS1rZXl2YWx1ZXNlcnZpY2UGaWNsb3VkA2NvbQAAHAABAAApAgAAAAAAAEUADABBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | dnsdump
;; opcode: QUERY, status: SUCCESS, id: 0
;; flags: rd ra

;; QUESTION SECTION:
;p61-keyvalueservice.icloud.com.		IN	AAAA

;; ANSWER SECTION:
p61-keyvalueservice.icloud.com.	66548	IN	CNAME	keyvalueservice.fe.apple-dns.net.
keyvalueservice.fe.apple-dns.net.	51	IN	AAAA	2620:149:a43:205::a
keyvalueservice.fe.apple-dns.net.	51	IN	AAAA	2620:149:a43:200::12
keyvalueservice.fe.apple-dns.net.	51	IN	AAAA	2620:149:a43:205::5
keyvalueservice.fe.apple-dns.net.	51	IN	AAAA	2620:149:a43:201::12
keyvalueservice.fe.apple-dns.net.	51	IN	AAAA	2620:149:a43:205::b
keyvalueservice.fe.apple-dns.net.	51	IN	AAAA	2620:149:a43:201::11
keyvalueservice.fe.apple-dns.net.	51	IN	AAAA	2620:149:a43:200::11
keyvalueservice.fe.apple-dns.net.	51	IN	AAAA	2620:149:a43:205::9

;; EDNS PSEUDOSECTION:
;; Version: 0, ext-rcode: 0; udp size: 1220
```

## Generating a binary DNS query

dnsdump AAAA example.com | curl -s https://dns.nextdns.io -H 'Content-Type:application/dns-message' --data-binary @- | dnsdump
