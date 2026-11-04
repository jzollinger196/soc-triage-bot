# Single-VM lab: real Wazuh alerts on an 8 GB laptop

This guide runs the **real Wazuh SIEM and the triage bot together in one small Linux VM**, while your Windows PC stays in charge: you control the VM from Windows, attack it from Windows, and read the reports on Windows. The AI runs on Groq, so nothing heavy runs locally.

Total time: about 60–90 minutes the first time, mostly waiting for installs.

---

## How the pieces fit together

```
            Windows PC (your control station)                    Ubuntu VM "wazuh-lab" (2 GB RAM)
 ┌──────────────────────────────────────────────┐    ┌──────────────────────────────────────────────┐
 │ VirtualBox (runs the VM)                     │    │ Wazuh manager: reads the VM's own SSH logs,  │
 │ PowerShell:                                  │    │   fires rules (5763 brute force, 5715 login) │
 │   ssh  -> control the VM                     │───▶│           │ integration hook                 │
 │   ssh with wrong passwords -> the "attack"   │    │           ▼                                  │
 │   scp  -> copy reports back to Windows       │    │ soc-triage bot: score, correlate, report  ───┼──▶ Groq API
 └──────────────────────────────────────────────┘    └──────────────────────────────────────────────┘    (gpt-oss-120b)
                     192.168.56.1   ◀── host-only network ──▶   192.168.56.101 (typical)
                                    NAT adapter ──▶ internet (for installs and Groq)
```

Why this split:

- **Wazuh only runs on Linux**, and the bot must run on the same machine as Wazuh, because Wazuh hands alerts to it through a local folder. So both go in the VM.
- **Windows stays your workstation.** Two network adapters connect the two worlds: a **host-only** adapter lets Windows and the VM talk to each other, and a **NAT** adapter gives the VM internet access.
- **The VM is the victim too.** Wazuh analyzes the manager's own logs, so typing wrong SSH passwords into the VM from Windows produces real Wazuh alerts. No attacker VM needed.
- **The AI is on Groq**, so you don't need Ollama running. Quit Ollama (tray icon → Quit) to free memory.

---

## Part 1: Create the VM (on Windows)

### 1.1 Install VirtualBox

```powershell
winget install Oracle.VirtualBox
```

Or download it from virtualbox.org. If VirtualBox later says VT-x or AMD-V isn't available, turn on virtualization in your BIOS.

### 1.2 Check the host-only network

Open VirtualBox → **File** → **Tools** → **Network Manager** (VirtualBox 7) → **Host-only Networks** tab.

- There should be an adapter with IPv4 address **192.168.56.1**. If the list is empty, click **Create**.
- Select it → **DHCP Server** tab → make sure **Enable Server** is ticked. This hands the VM an address automatically.

### 1.3 Download Ubuntu Server

Download **Ubuntu Server 24.04 LTS** from ubuntu.com/download/server. It's an `.iso` file of about 2.5 GB. Get the **Server** edition, not Desktop: no graphical desktop means much less RAM.

### 1.4 Create the VM

VirtualBox → **New**:

| Setting | Value |
|---|---|
| Name | `wazuh-lab` |
| ISO Image | the Ubuntu Server `.iso` |
| Skip Unattended Installation | **ticked** |
| Base Memory | **2048 MB** |
| Processors | **2** |
| Hard disk | **20 GB** |

Click **Finish**, then **before starting it**: select the VM → **Settings** → **Network**:

- **Adapter 1:** leave as **NAT**.
- **Adapter 2:** tick **Enable Network Adapter**, set *Attached to* **Host-only Adapter**, and pick the adapter from 1.2.

### 1.5 Install Ubuntu

Select the VM → **Start**. Use arrow keys, Space and Enter:

1. Language and keyboard: defaults.
2. Install type: **Ubuntu Server** (not "minimized").
3. Network: you should see **two** interfaces. One gets `10.0.2.15` (NAT), the other something like `192.168.56.101` (host-only). Write down the `192.168.56.x` address. If the second one has no address, finish anyway; Part 2 shows how to check.
4. Proxy and mirror: defaults. Storage: **Use an entire disk** (it's the VM's virtual disk), then **Done** → **Continue**. Ubuntu only gives the system about half the disk; Part 3 adds the rest.
5. Profile, using these exact names because the bot's lab config expects them:
   - Your name: anything
   - **Your server's name: `wazuh-lab`**
   - **Username: `labadmin`**
   - Password: one you'll remember. This is a lab password: don't reuse a real one.
6. Ubuntu Pro: skip. **SSH: tick "Install OpenSSH server".** Featured snaps: none.
7. Wait for the install → **Reboot Now**. If it asks you to remove the installation medium, press Enter.
8. Log in at the VM window as `labadmin`.

---

## Part 2: Connect from Windows

In the VM window, find its address:

```bash
ip -br addr
```

Use the `192.168.56.x` address on the line starting `enp0s8`. This guide uses **192.168.56.101**; substitute yours everywhere.

If `enp0s8` has no address, turn on automatic addressing for it, then check again:

```bash
sudo netplan set ethernets.enp0s8.dhcp4=true
sudo netplan apply
ip -br addr
```

From now on, work from **PowerShell on Windows**, where copy and paste work properly:

```powershell
ssh labadmin@192.168.56.101
```

Type `yes` the first time, then your password. You're now controlling the VM. Every `bash` block below runs in this SSH session.

---

## Part 3: Install the Wazuh manager (in the VM)

### 3.1 Prepare the VM

These three changes prevent problems found while building this lab (see [RESULTS.md](RESULTS.md)).

```bash
# 1. Give the system the whole virtual disk (Ubuntu leaves about half unused)
sudo lvextend -r -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
df -h /

# 2. Stop rsyslog merging identical lines into "message repeated N times".
#    Otherwise Wazuh can't count repeated failed logins and misses brute force.
sudo sed -i 's/^\$RepeatedMsgReduction on/$RepeatedMsgReduction off/' /etc/rsyslog.conf
sudo systemctl restart rsyslog
grep RepeatedMsgReduction /etc/rsyslog.conf

# 3. Give Wazuh up to 5 minutes to start (a 2 GB VM can exceed the default 90 seconds)
sudo mkdir -p /etc/systemd/system/wazuh-manager.service.d
printf '[Service]\nTimeoutStartSec=300\n' | sudo tee /etc/systemd/system/wazuh-manager.service.d/timeout.conf
sudo systemctl daemon-reload
```

`df` should show about 18 GB, and `grep` should print `$RepeatedMsgReduction off`.

### 3.2 Install the manager

Only the manager: the indexer and dashboard need far more RAM, and the bot doesn't need them.

```bash
sudo apt-get update && sudo apt-get install -y gnupg apt-transport-https curl
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update && sudo apt-get install -y wazuh-manager
sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-manager
sudo systemctl status wazuh-manager --no-pager
```

The last command should show **active (running)**. Press `q` if it waits.

### 3.3 Turn off the vulnerability scanner

Wazuh's vulnerability detection downloads many gigabytes of data. In this lab it filled the disk within an hour, which **silently stopped log collection and detection**. The lab doesn't need it, and the manager-only install has no indexer to send its results to, so switch both off:

```bash
sudo sed -i '/<vulnerability-detection>/,/<\/vulnerability-detection>/s|<enabled>yes</enabled>|<enabled>no</enabled>|' /var/ossec/etc/ossec.conf
sudo sed -i '/<indexer>/,/<\/indexer>/s|<enabled>yes</enabled>|<enabled>no</enabled>|' /var/ossec/etc/ossec.conf
sudo grep -A1 -E "<vulnerability-detection>|<indexer>" /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
sudo sh -c 'rm -rf /var/ossec/tmp/* /var/ossec/queue/vd/feed/*'
df -h /
```

`grep` should show `<enabled>no</enabled>` under both. The `sh -c` wrapper matters: without it, the `*` is expanded by your own account, which can't see inside `/var/ossec`, and nothing gets deleted.

### 3.4 Check the SSH log source

Make sure Wazuh reads the VM's SSH login log:

```bash
sudo grep -n "auth.log\|journald" /var/ossec/etc/ossec.conf
```

If that prints at least one line, you're set. If it prints nothing, you'll add the log source in Part 4.

---

## Part 4: Install the bot (in the VM)

### 4.1 Copy the project to the VM

Copy the project **zip** rather than the folder: some versions of Windows' built-in `scp` fail when copying folders (`stat remote: No such file or directory`), and Windows `scp` doesn't understand `~`. In a **second PowerShell window** on Windows, using your Windows username and the zip's actual name:

```powershell
scp C:\Users\YOUR-WINDOWS-USER\Downloads\soc-triage-bot.zip labadmin@192.168.56.101:/home/labadmin/
```

Then, in the SSH session:

```bash
sudo apt-get install -y unzip
cd ~ && unzip -o soc-triage-bot.zip
ls ~/soc-triage-bot
```

You should see `config.lab.json`, `deploy`, `docs`, `samples`, `soc_triage` and `wazuh`. Using the zip also keeps your Windows test setup and any secrets files off the VM.

### 4.2 Run the installer

Back in the SSH session:

```bash
cd ~/soc-triage-bot
sudo bash deploy/install.sh
```

### 4.3 Configure it

Use the ready-made lab config, so there's no JSON to type:

```bash
sudo cp ~/soc-triage-bot/config.lab.json /etc/soc-triage/config.json
```

Add your Groq key. Replace the placeholder with your real key from console.groq.com → API Keys:

```bash
echo "SOC_TRIAGE_API_KEY=gsk_paste_your_key_here" | sudo tee -a /etc/soc-triage/secrets.env > /dev/null
```

Let `labadmin` read the reports, so you can copy them to Windows later. This takes effect the next time you log in:

```bash
sudo usermod -aG soctriage labadmin
```

### 4.4 Connect Wazuh to the bot

Append the integration settings. This is the step that makes Wazuh hand alerts to the bot:

```bash
sudo tee -a /var/ossec/etc/ossec.conf < ~/soc-triage-bot/wazuh/ossec-integration-block.xml > /dev/null
```

**Only if the `grep` in Part 3 printed nothing**, also add the SSH log source:

```bash
sudo tee -a /var/ossec/etc/ossec.conf < ~/soc-triage-bot/wazuh/ossec-authlog-block.xml > /dev/null
```

Restart both services and check:

```bash
sudo systemctl restart wazuh-manager soc-triage
soc-triage check
```

`check` should show `[ OK ] LLM: API key found; requests will go to https://api.groq.com/openai/v1/chat/completions`. It only confirms the key is present; the next step really tests Groq.

### 4.5 Test the bot before attacking anything

Drop one sample alert into the bot's inbox:

```bash
sudo install -o soctriage -g wazuh -m 0660 ~/soc-triage-bot/samples/05_web_scan_with_prompt_injection.json /var/lib/soc-triage/spool/test-1.json
sleep 20
sudo ls -R /var/lib/soc-triage/reports
sudo sh -c 'grep "Analysis source" /var/lib/soc-triage/reports/*/*.md'
```

You want `Analysis source: openai:openai/gpt-oss-120b`. If it says `fallback`, see Troubleshooting.

---

## Part 5: Attack it and get real alerts (from Windows)

Open a third view to watch the bot live. In the SSH session:

```bash
sudo journalctl -u soc-triage -f
```

### 5.1 The brute force

In a **new PowerShell window on Windows**, run this **three times in a row**. Each time, type a **wrong password three times**:

```powershell
ssh labadmin@192.168.56.101
```

That's 9 failed logins in under two minutes. Wazuh rule **5763** ("sshd: brute force trying to get access to the system") fires at level 10, and within seconds the bot's log shows a new **High** incident.

### 5.2 The compromise

Within 15 minutes, **log in correctly** from the same PowerShell window:

```powershell
ssh labadmin@192.168.56.101
```

Wazuh recognizes the pattern itself: instead of a plain login alert (rule 5715), it raises rule **40112**, "Multiple authentication failures followed by a success" (level 12). The bot turns it into a **Critical "possible account compromise"** incident:

| Factor | Points |
|---|---|
| Rule 40112 at level 12 | 48 |
| Rule only fires after 2+ matching events | 2 |
| 1 earlier alert from the same IP | 3 |
| `labadmin` is a privileged (sudo) account | 10 |
| Wazuh correlated failed logins followed by a success | 45 |
| `wazuh-lab` is a high-criticality asset | 15 |
| **Total (capped at 100)** | **100** |

If the login alert arrives as plain rule 5715 instead, the bot makes the same connection itself from its own history and still rates it Critical.

Press Ctrl+C to stop watching the log.

### 5.3 Check that Wazuh itself saw it

```bash
sudo grep -B1 -E "Rule: (5763|40112|5715)" /var/ossec/logs/alerts/alerts.log | tail
```

The line above each rule is its timestamp (UTC). This is proof for your write-up that the detections came from the real SIEM.

You may see each alert twice: Wazuh can read the VM's logins from two sources (`/var/log/auth.log` and the systemd journal), and the bot then writes two reports for the same event.

---

## Part 6: Read the reports on Windows

Log out and back in once, so the group change from 4.3 applies. Then, from PowerShell on Windows:

```powershell
scp -r labadmin@192.168.56.101:/var/lib/soc-triage/reports C:\Users\YOUR-WINDOWS-USER\Desktop\lab-reports
explorer C:\Users\YOUR-WINDOWS-USER\Desktop\lab-reports
```

If your Desktop is synced by OneDrive, the path is `C:\Users\YOUR-WINDOWS-USER\OneDrive\Desktop\lab-reports`. Reports are in a folder named with **today's date**, since these are real alerts. Open them with Notepad or VS Code (Ctrl+Shift+V for the formatted view).

To read them directly in the VM instead:

```bash
sudo sh -c 'ls /var/lib/soc-triage/reports/*/'
sudo sh -c 'less /var/lib/soc-triage/reports/*/INC-*.md'      # q to quit
```

**What to save for your write-up:**
- the Critical compromise report,
- the matching lines from `alerts.log` (5.3),
- whether the AI correctly called the compromise a compromise. Compare it with the 3B local model's false-positive mistake on sample 03.

---

## Daily use

| You want to… | Do this |
|---|---|
| Start the lab | VirtualBox → select `wazuh-lab` → arrow next to **Start** → **Headless Start**. Wait about a minute, then `ssh labadmin@192.168.56.101` |
| Check everything is running | `sudo systemctl status wazuh-manager soc-triage --no-pager` |
| Watch the bot | `sudo journalctl -u soc-triage -f` |
| Stop the lab | `sudo poweroff` in the VM (avoid VirtualBox's "Power Off", which is like pulling the plug) |
| Check disk space | `df -h /` should stay well below 100%. If it climbs, see Troubleshooting |

Your normal SSH logins are also sent to the bot, but they're only recorded for correlation: no report is written unless a brute-force alert from the same IP came first.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ssh` from Windows times out | Check Adapter 2 is **Host-only** (1.4) and its DHCP server is on (1.2). In the VM window, `ip -br addr` should show a `192.168.56.x` address on `enp0s8` |
| `enp0s8` has no address | In the VM: `sudo netplan set ethernets.enp0s8.dhcp4=true && sudo netplan apply` |
| No 5763 alert after the failed logins | Run `sudo tail -n 20 /var/log/auth.log` to see whether the failures were logged. If they were, re-check Part 3's `grep` and the auth-log block. The 8 failures must happen within about two minutes |
| Alerts appear in `alerts.log` but no reports | `sudo tail /var/ossec/logs/integrations.log`. If it says `Permission denied` for the spool, you installed with an older `install.sh`: run `sudo chmod o+x /var/lib/soc-triage && sudo chgrp wazuh /var/lib/soc-triage/spool && sudo chmod 2770 /var/lib/soc-triage/spool && sudo usermod -aG wazuh soctriage && sudo systemctl restart soc-triage wazuh-manager` |
| Disk fills up (`df -h /` at 100%), logging and Wazuh stop | Wazuh's vulnerability scanner downloads many GB. Disable it: in `/var/ossec/etc/ossec.conf` set `<enabled>no</enabled>` inside `<vulnerability-detection>` and `<indexer>`, stop Wazuh, then `sudo sh -c 'rm -rf /var/ossec/tmp/* /var/ossec/queue/vd/feed/*'` |
| Failed logins show as `message repeated N times` and 5763 never fires | Ubuntu's rsyslog compresses repeated lines, hiding them from Wazuh: `sudo sed -i 's/^\$RepeatedMsgReduction on/$RepeatedMsgReduction off/' /etc/rsyslog.conf && sudo systemctl restart rsyslog` |
| Files pile up in the spool | `sudo journalctl -u soc-triage -n 50 --no-pager` |
| Report says `fallback` with HTTP 401 | Groq key wrong. Fix it: `sudo nano /etc/soc-triage/secrets.env` (the last `SOC_TRIAGE_API_KEY=` line wins), then `sudo systemctl restart soc-triage` |
| HTTP 404 "model not found" | Groq retired the model. List current ones and update `"model"` in `/etc/soc-triage/config.json` (`sudo nano`) |
| HTTP 429 | Groq's free per-minute limit. Wait a minute; later alerts will work |
| Login after brute force wasn't Critical | It must come from the same IP, within 15 minutes, as user `labadmin`, and `/etc/soc-triage/config.json` must be the lab config (`grep wazuh-lab /etc/soc-triage/config.json`) |
| `scp` of reports says permission denied | Log out and back in after `usermod` (4.3), or run `sudo chmod -R g+rX /var/lib/soc-triage/reports` |
| Laptop is very slow | Close the VM window (keep it running headless), quit Ollama, close browser tabs |
