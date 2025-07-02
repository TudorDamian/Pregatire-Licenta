# Packet Sniffer – Ghid pentru Filtrare

Această aplicație oferă două tipuri de filtre, în funcție de momentul aplicării:

---

## 🔹 Filtrare în timp real (captură live)

> Se aplică înainte de capturare, pe baza expresiei BPF (Berkeley Packet Filter).  
> Sintaxa este compatibilă cu Wireshark/tcpdump.

### ✅ Protocoale

| Filtru      | Descriere                         |
|-------------|-----------------------------------|
| `ip`        | Pachete IPv4                      |
| `ip6`       | Pachete IPv6                      |
| `arp`       | Pachete ARP                       |
| `icmp`      | Pachete ICMP (ping)               |
| `tcp`       | Pachete TCP                       |
| `udp`       | Pachete UDP                       |

### ✅ Adrese IP

| Filtru                  | Descriere                          |
|-------------------------|------------------------------------|
| `src host 192.168.1.1`  | IP sursă specific                  |
| `dst host 8.8.8.8`      | IP destinație specific             |
| `host 10.0.0.5`         | IP sursă sau destinație            |

### ✅ Porturi

| Filtru           | Descriere                        |
|------------------|----------------------------------|
| `tcp port 80`    | Pachete HTTP                     |
| `udp port 53`    | Pachete DNS                      |
| `port 443`       | Orice pachet pe port 443         |

### ✅ Combinații

| Filtru                                          | Descriere                                 |
|-------------------------------------------------|--------------------------------------------|
| `tcp and port 443`                              | Pachete TCP doar pe portul 443            |
| `ip and udp and port 53`                        | Pachete DNS peste UDP (IPv4)              |
| `src host 192.168.0.10 and tcp port 22`         | SSH de la 192.168.0.10                    |
| `host 192.168.1.1 and not icmp`                 | Orice trafic fără ICMP                    |

### ✅ Rețele

| Filtru                  | Descriere                          |
|-------------------------|------------------------------------|
| `net 192.168.1.0/24`    | Subrețeaua 192.168.1.x             |
| `ip src net 10.0.0.0/8` | IP sursă în 10.x.x.x               |

---

## 🔹 Filtrare locală (după captură)

> Se aplică după oprirea capturii, pe pachetele deja salvate în memorie.

### ✅ Suportă sintaxă extinsă, inclusiv:
- `==`, `!=`
- `and`, `or`
- expresii pe câmpuri IP, porturi și protocoale

### ✅ Exemple:

| Filtru                                          | Descriere                                 |
|-------------------------------------------------|--------------------------------------------|
| `ip.src == 192.168.1.10`                        | Pachete cu sursa 192.168.1.10              |
| `ip.dst == 8.8.8.8`                             | Pachete către Google DNS                   |
| `tcp.port == 443`                               | HTTPS                                      |
| `udp.port != 53`                                | Pachete UDP diferite de DNS                |
| `proto == tcp`                                  | Doar TCP                                   |
| `ip and icmp`                                   | Pachete ICMP în IPv4                       |
| `ip.src == 192.168.0.1 and tcp.port == 80`      | HTTP de la adresa locală                   |

---

## ℹ️ Alte detalii

- Când apeși **Enter** în câmpul de filtrare după Stop → se aplică filtrarea locală.
- Când apeși **Start** sau **Restart**, dacă filtrul este complet, se aplică la captură (live).
- Placeholderul „Apply a display filter…” nu declanșează filtrare dacă este neschimbat.

---

## ❗ Limitări

- În captura live nu sunt suportate: `!=`, `>`, `contains`, `startswith` etc.
- Acestea sunt disponibile doar în filtrarea locală (internă, în aplicație).

---

## 🧠 Recomandare

Folosește:
- expresii tip `ip.src == x.x.x.x and tcp.port == y` pentru filtrare locală
- expresii `src host x.x.x.x and tcp port y` pentru captura live
