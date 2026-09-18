# HTB Web Fuzzing — Skill Assessment Writeup

A step-by-step writeup of how I solved the **Web Fuzzing** Skill Assessment on Hack The Box, using `ffuf` and `gobuster` for directory, extension, parameter, and virtual host fuzzing.

> **Note:** IP/domain values below are placeholders standing in for the assessment target. Replace `<TARGET_IP>` and `<PORT>` with your own instance values if you're following along.

---

## Tools Used
- [ffuf](https://github.com/ffuf/ffuf)
- [gobuster](https://github.com/OJ/gobuster)
- [SecLists](https://github.com/danielmiessler/SecLists) — `Discovery/Web-Content/common.txt`

---

## Step 1 — Initial Directory Fuzzing

Started with a standard directory brute-force against the target using `ffuf` and the SecLists common wordlist.

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<TARGET_IP>:<PORT>/FUZZ
```

**Result:** Found an `admin` directory.

---

## Step 2 — Recursive Fuzzing with Extensions

Next, I fuzzed the `admin` directory recursively while also appending common web extensions to catch files that might not be indexed by name alone.

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<TARGET_IP>:<PORT>/admin/FUZZ -e .php,.html,.txt -recursion
```

**Result:** Found `panel.php`.

Visiting `panel.php` revealed an `accessID` GET parameter.

---

## Step 3 — Parameter Value Fuzzing

With the `accessID` parameter identified, I fuzzed its value directly. To cut down on noise from the default/error page, I filtered out responses by size (`-fs`) once I identified the common "invalid" response size.

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u "http://<TARGET_IP>:<PORT>/admin/panel.php?accessID=FUZZ" -fs 58
```

**Result:** Found a valid value — `getaccess`.

Visiting:

```
http://<TARGET_IP>:<PORT>/admin/panel.php?accessID=getaccess
```

revealed a reference to a vhost: `fuzzing_fun.htb`.

---

## Step 4 — Virtual Host Discovery

Added the discovered vhost to `/etc/hosts`:

```bash
echo "<TARGET_IP> fuzzing_fun.htb" | sudo tee -a /etc/hosts
```

Then ran `gobuster` in `vhost` mode against the base domain to look for further hidden subdomains:

```bash
gobuster vhost -u http://fuzzing_fun.htb:<PORT> -w /usr/share/seclists/Discovery/Web-Content/common.txt --append-domain | grep -i "Status: 200"
```

**Result:** Found a second hidden vhost — `hidden.fuzzing_fun.htb`.

---

## Step 5 — Enumerating the Hidden Vhost

Added the new vhost to `/etc/hosts` as well:

```bash
echo "<TARGET_IP> hidden.fuzzing_fun.htb" | sudo tee -a /etc/hosts
```

Visiting `http://hidden.fuzzing_fun.htb:<PORT>` revealed a hint pointing to a `/godeep` path.

---

## Step 6 — Final Recursive Fuzzing

Ran a recursive `ffuf` scan against the `/godeep` directory to dig through the final layer.

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u "http://hidden.fuzzing_fun.htb:<PORT>/godeep/FUZZ" -recursion
```

**Result:** Uncovered the final nested path, completing the assessment. 🎯

---

## Summary

| Step | Technique | Tool | Discovery |
|------|-----------|------|-----------|
| 1 | Directory fuzzing | ffuf | `admin/` |
| 2 | Recursive + extension fuzzing | ffuf | `panel.php` |
| 3 | Parameter value fuzzing | ffuf | `accessID=getaccess` |
| 4 | Vhost fuzzing | gobuster | `fuzzing_fun.htb` |
| 5 | Vhost enumeration | gobuster/manual | `hidden.fuzzing_fun.htb` |
| 6 | Recursive directory fuzzing | ffuf | Final flag path |

### Key Takeaway
Web fuzzing is rarely a single scan — it's an **iterative process**. Each discovery (a directory, a parameter, a vhost) opens up a new attack surface that requires its own fuzzing strategy: content, extensions, parameters, and virtual hosts all need to be enumerated separately.

---

*Writeup by Gupteswar Achary — Hack The Box Web Fuzzing Skill Assessment*
