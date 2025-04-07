# Packet Sniffer – Exemple de Filtre

Această aplicație acceptă filtre de tip **BPF (Berkeley Packet Filter)**, la fel ca Wireshark sau tcpdump.

---

## Protocoale generale

| Filtru      | Descriere                         |
|-------------|-----------------------------------|
| `ip`        | Pachete IPv4                      |
| `ip6`       | Pachete IPv6                      |
| `arp`       | Pachete ARP                       |
| `icmp`      | Pachete ICMP (ping)               |
| `tcp`       | Pachete TCP                       |
| `udp`       | Pachete UDP                       |

---

## Adrese IP

| Filtru                  | Descriere                                    |
|-------------------------|----------------------------------------------|
| `src host 192.168.1.1`  | Doar sursa IP 192.168.1.1                    |
| `dst host 8.8.8.8`      | Doar destinația IP 8.8.8.8                   |
| `host 10.0.0.5`         | Orice sens (src sau dst) pentru 10.0.0.5     |

---

## Porturi

| Filtru           | Descriere                        |
|------------------|----------------------------------|
| `tcp port 80`    | Pachete HTTP (port 80)           |
| `udp port 53`    | Pachete DNS (port 53 UDP)        |
| `port 443`       | Orice pachet pe port 443         |

---

## Combinații logice

| Filtru                                          | Descriere                                 |
|-------------------------------------------------|--------------------------------------------|
| `tcp and port 443`                              | Pachete TCP doar pe portul 443            |
| `ip and udp and port 53`                        | Pachete DNS peste UDP (IPv4)              |
| `src host 192.168.0.10 and tcp port 22`         | SSH de la 192.168.0.10                    |
| `host 192.168.1.1 and not icmp`                 | Orice de la/către 192.168.1.1, fără ICMP  |

---

## Rețele

| Filtru                  | Descriere                          |
|-------------------------|------------------------------------|
| `net 192.168.1.0/24`    | Subrețeaua 192.168.1.x             |
| `ip src net 10.0.0.0/8` | IP sursă în 10.x.x.x               |

---

## Alte exemple utile

- `tcp[tcpflags] & tcp-syn != 0` → doar SYN (început conexiune TCP)
- `ether src 00:11:22:33:44:55` → pachete de la MAC specific

---

## Notă

- Nu se folosesc: `==`, `!=`, `contains` – acestea nu sunt suportate în BPF.
- Filtrul este aplicat la nivel de captură, nu post-procesare.
