# UniFi logs into Wazuh 5.x

How UniFi Network events (admin logins, port forward changes, blocked traffic, ...) reach
Wazuh 5.0.0-rc2 and turn into findings. Written 2026-11-10 from the setup that was built.

## Why this is different from 4.x

In 4.x the manager received UniFi's syslog itself (`<remote><connection>syslog`, port 514)
and decoded it with XML decoders and rules. 5.x removed all three:

| | 4.x | 5.x |
|---|---|---|
| Syslog input | manager `remoted`, port 514 | rsyslog on a host + a Wazuh agent on that host |
| Decoders | XML on the manager | YAML assets of an integration, run by the Engine |
| Rules | XML, numeric levels, `if_sid` chains | Sigma YAML, keyword levels, one self-contained rule per document |
| Alerts | alerts | findings, produced by a detector |

## Overview

```
UniFi (UDP 514) -> rsyslog container -> /logs/<sender-ip>.log (shared volume)
   -> Wazuh agent container (reads /var/log/remote/*.log) -> Wazuh manager (1517)
   -> decoder/unifi-cef/0 -> rules -> detector "unifi" -> findings
```

| Piece | Where |
|---|---|
| UniFi syslog target | UniFi Network: Settings > System > Integrations > Activity Logging > SIEM Server, address `10.13.0.12`, port `514` |
| Receiver stack (rsyslog + agent) | `wazuh_syslog/` in the `compose` repo, deployed by Komodo on `pve-docker-int01` (10.13.0.12) |
| Firewall on that host | `ufw allow from <UDM IP> to any port 514 proto udp` (host networking, so ufw applies) |
| Decoder, rules | this repo: `decoders/custom_unifi.yml`, `rules/custom_unifi.yml` |
| Wazuh content | integration `unifi`, root decoder, decoder, 6 rules, detector `unifi` |

## 1. The receiver stack

Files in `compose/wazuh_syslog/`: `compose.yaml`, `rsyslog.conf`, `10-localfile.sh`, `.env.example`.

- rsyslog runs with `network_mode: host`, which keeps the real sender IP in the file names
  and lets `ufw` filter port 514 (Docker-published ports bypass ufw).
- The agent container (`wazuh/wazuh-agent:5.0.0-rc2`) mounts the same volume read-only.
  `10-localfile.sh` adds the `<localfile>` for `/var/log/remote/*.log` before it starts.
- Enrollment: set `WAZUH_ENROLLMENT_TOKEN` on the Komodo stack (never in git). Mint it on the
  Wazuh VM:
  ```bash
  sudo docker exec single-node-wazuh.manager /var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address 10.13.0.127 --ttl 1h
  ```
  It is only needed on first start; the agent keeps its key in the `wazuh-agent-etc` volume.
- Check it works, on the Docker host:
  ```bash
  sudo docker exec rsyslog_wazuh ls -la /logs
  ```
  You should see a file per sender (the UDM's address, plus any UniFi device that sends syslog).

## 2. What UniFi sends

The UDM sends CEF. One real line (names and IPs replaced), event 545 "Config Created":

```
2026-11-10T00:25:29+00:00 HeimeUDM CEF: 0|Ubiquiti|UniFi Network|11.1.47|545|Config Created|5|UNIFIcategory=Audit ... UNIFIsettingsSection=Port forwarding UNIFIsettingsEntry=a UNIFIadmin=Some Name src=1.1.1.1 cnt=10 ... msg=Some Name created a Port forwarding. Source IP: 1.1.1.1
```

Event IDs confirmed from real lines: 203 blocked by a firewall policy, 544 admin access,
545 config created, 547 config paused, 548 config resumed, 549 config removed (the
`UNIFIsettingsSection` says what was changed, e.g. `Port forwarding`). Still assumed: 515
devices offline. 546 is "config modified". The decoder classifies every `UNIFIcategory=Audit` event by
`UNIFIsettingsSection`, so create, modify, pause, resume, remove and reorder of a firewall policy
or port forward are all covered. The reorder event ID has not been seen; if it is not
classified, paste its line.

Access points and switches also send plain device syslog (kernel, hostapd, ...). The
decoder only matches lines containing `|Ubiquiti|UniFi Network|`, so those are not decoded.

## 3. What was created in Wazuh

All in Ruleset management, created in the Draft space, promoted Draft > Test > Custom.

| Item | Name / detail |
|---|---|
| Integration | `unifi`, category Network Activity (title must equal every rule's `logsource.product`) |
| Root decoder | `decoder/core-wazuh-message/0`, a copy of the standard one, set as the space's root decoder |
| Decoder | `decoder/unifi-cef/0`, parent `decoder/core-wazuh-message/0` |
| Detector | `unifi`, data source `wazuh-events-v5-network-activity`, Custom space, every 1 minute |

Rules (4.x level -> 5.x level):

| Rule | `event.action` | 4.x | 5.x |
|---|---|---|---|
| UniFi port forwarding changed | `unifi-portforward-changed` | 222301, 16 | critical |
| UniFi firewall policy changed | `unifi-firewall-policy-changed` | 222311, 12 | high |
| UniFi devices offline | `unifi-devices-offline` | 222312, 12 | high |
| UniFi admin access | `unifi-admin-access` | 222341, 8 | medium |
| UniFi blocked domain (new) | `unifi-firewall-blocked`, with `destination.domain` | - | informational |
| UniFi other event | any other, via `not filter` | 222300, 3 | informational |

The decoder writes Wazuh Common Schema fields (`user.name`, `source.ip`, `destination.domain`,
`destination.ip`, `destination.port`, `rule.name`, `event.code`, `event.action`, `message`),
because 5.x rules can only match schema fields. For blocked traffic (event 203) it also keeps
the client IP (`source.ip`), client hostname (`source.domain`), source zone
(`observer.ingress.zone`) and destination country (`destination.geo.country_iso_code`), which
the dashboard uses.

## 4. How it was built in the dashboard (and the traps)

1. **Space selector (top right of every page): Draft, Test, Custom, Standard.** Standard is
   read-only, so Create is greyed out there. Switch to Draft first.
2. **Create the integration:** Overview > Actions > Create. Title lowercase letters, digits,
   hyphens or underscores; pick a category.
3. **Root decoder.** Promotion fails with "Root decoder not defined in the space" until the
   draft space has one. Create `decoder/core-wazuh-message/0` in the draft space with the same
   content as the standard one (it only parses the raw event as JSON), then Overview > Actions
   > Edit and select it as the root decoder. Do not pick your own decoder as root.
4. **Decoder:** Decoders > Actions > Create > YAML Editor. It needs `parents:
   decoder/core-wazuh-message/0`.
5. **Rules:** Rules > Actions > Create > YAML Editor, one rule per create, integration `unifi`.
6. **Promote:** Overview > Actions > Promote, type `promote` to confirm. Draft cannot be
   tested; promote to Test first. "It can take a few minutes for the changes to apply".
7. **Log test** (in the Test space): pick integration `unifi`, paste a line from
   `validate.log`, then Test. Check the Normalization and Detection tabs.
8. **Promote Test > Custom**, then create the **detector** (Detectors > Create detector): data
   source `wazuh-events-v5-network-activity`, rules space **Custom**, integration `unifi`.
   Without a detector the rules never run.

Editing later: change it in Draft, promote to Test, re-run Log test, then promote to Custom.
The detector picks up Custom-space changes.

## 5. Test lines and expected results

`validate.log` holds anonymized lines; `answers.md` the expected output.

| Line | Expect in Log test |
|---|---|
| Event 545 port forward | `event.action unifi-portforward-changed`, `user.name Some Name`, `source.ip 1.1.1.1`, `event.code 545`; rule UniFi port forwarding changed (critical) |
| Event 203 blocked | `event.action unifi-firewall-blocked`, `destination.domain example.test`, `destination.ip 1.1.1.2`, `destination.port 80`, `rule.name Block all`; rule UniFi blocked domain (informational) |

Both passed in the Test space on 2026-11-10 ("Parsed into 19 / 21 fields, 1 rule matched").

## 6. Dashboard: "UniFi blocked traffic"

File: `dashboards/unifi-blocked-traffic.ndjson` (OpenSearch Dashboards saved objects: 1 dashboard
and 8 visualizations, fixed IDs, built on the index pattern `wazuh-events-v5-network-activity*`).
Every panel is limited to `event.action:"unifi-firewall-blocked"` (event 203). Default range:
last 24 hours.

| Panel | Shows |
|---|---|
| Blocked connections | total count |
| Most blocked domains | `destination.domain`, only blocks that had a domain |
| Most blocked destinations without a domain | `destination.ip`, for blocks UniFi had no domain for |
| Blocks over time by policy | stacked bars by `rule.name` (the firewall policy) |
| Most blocked clients | `source.ip` and `source.domain` (client hostname) |
| Most blocked domains per client IP | `source.ip`, then `destination.domain` |
| Blocks by source zone | `observer.ingress.zone` (IOT, Servers, ...) |
| Blocks by destination country | `destination.geo.country_iso_code` |

Import it: Dashboards Management > Saved objects > Import, pick the file, choose "Check for
existing objects" (keeps the fixed IDs, so re-importing overwrites instead of duplicating). Open
it at `/app/dashboards#/view/unifi-blocked-traffic`.

Notes:
- The client IP, client hostname, zone and country fields are written by the decoder from
  2026-11-10 onward. Older blocked events lack them, so the per-client, zone and country panels
  only fill from that point. The domain, destination IP and policy panels include older events.
- Many blocks have no domain (UniFi only knew the IP), which is why there are two tables.
- To change a panel, edit it in the dashboard, then export the dashboard and its
  visualizations back over this file.

## 7. Troubleshooting

| Symptom | Check |
|---|---|
| Nothing in `/logs` on the Docker host | UniFi target address is `10.13.0.12:514`; ufw allows the UDM; `sudo tcpdump -ni any udp port 514` |
| File exists but no findings | Agent container enrolled and connected (`docker logs wazuh_agent_syslog`); logcollector log mentions the file; wait a few minutes after promoting |
| Log test works, no findings | Detector exists, is Active, uses space **Custom**, data source `wazuh-events-v5-network-activity` |
| Promote blocked: root decoder | Section 4, step 3 |
| Create greyed out | Wrong space; switch to Draft |
| Log test says draft cannot be tested | Promote to Test first |
| A field is empty in Log test | The parse expression for that field; paste the real line and compare |

## 8. Not ported, and open items

- **Suppression rules.** `custom_supress.xml` (Ceph SMART polls via sudo) cannot be ported:
  5.x has no level 0. Not converted.
- **4.x rules not yet ported:** 222345 fixed IP, 222351 version update, 222361 device
  connection. They need a real line of each event first.
- **Event 544** (admin access) is confirmed by a live finding. **Event 515** (devices
  offline) is still assumed to look like 545; confirm with a real line.
- **Noise.** The agent reads every file in `/var/log/remote/`, including device logs. Lines
  the decoder does not match are unclassified and, by default, not indexed, but they still
  travel to the manager. Restrict the `<localfile>` to the UDM's file if wanted.
- **No log rotation** on the `remote-logs` volume yet.
- **Volume.** Blocked traffic from IoT devices repeats all day; the blocked-domain rule can be
  noisy. Narrow it by zone or policy if so.
- **Release candidate.** Wazuh 5.0.0-rc2; behaviour may change before the final release.
- **Status:** both test lines pass in Log test and the content is promoted to Custom with an
  active detector. Confirmed end to end on 2026-11-10: a real admin login produced a finding
  (agent `pve-wazuh-syslog`, integration `unifi`, rule "UniFi admin access", medium). Also
  confirmed live: a blocked-domain finding, and four critical "UniFi port forwarding changed"
  findings for a port forward that was created, paused, resumed and removed (one finding per
  event). Firewall policy changed and devices offline have not yet been seen live.
