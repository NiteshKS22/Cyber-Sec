## Task 2: Events and Alerts

### The View from the Cockpit
Imagine this: I'm standing behind my mentor, looking at their monitors. It looks like the Matrix. Lines of text are scrolling, dashboards are blinking, and colors are shifting from green to red.

I see hundreds of alerts:
* "Email Marked as Phishing" (Common, annoying)
* "Unusual Gmail Login Location" (Suspicious)
* **"Unapproved Mimikatz Usage"** (Terrifying. This one was in a bright red column.)

At first, it looked like chaos. But then I learned the method behind the madness.

### The Funnel: From Events to Alerts
Not everything that happens on a computer is scary. In fact, 99.9% of it is boring. I learned that there is a strict lifecycle that turns a normal action into a security alert.

1.  **The Event:** A user logs in, opens a file, or visits a website. (Millions of these happen daily).
2.  **The Log:** The system (OS, Firewall, Cloud) records this event.
3.  **The Shipping:** These logs are packed up and sent to a central brain (SIEM or EDR).
4.  **The Alert:** This is the filter. The security tool analyzes the millions of logs and only notifies us if something looks **suspicious** or **anomalous**.

**Why do we need this?**
If we didn't have alerts, I would have to manually read millions of text logs every day. Alerts filter those millions down to just a few dozen actionable items.

### The Analyst's Toolkit (Alert Management)
Where do these alerts actually go? It depends on the tool. Here is the stack I need to master:

| Tool Category | Examples | My Take |
| :--- | :--- | :--- |
| **SIEM** (Security Information and Event Management) | *Splunk ES, Elastic* | **The Main Brain.** This is where most SOC teams live. It collects logs from everywhere and has the best alert management. |
| **EDR / NDR** (Endpoint/Network Detection & Response) | *MS Defender, CrowdStrike* | **The Reflexes.** These tools watch specific devices or networks. While they have their own dashboards, we usually feed their data into the SIEM. |
| **SOAR** (Security Orchestration, Automation and Response) | *Splunk SOAR, Cortex XSOAR* | **The Autopilot.** Bigger teams use this to automate the boring stuff. It brings alerts from different tools into one place. |
| **ITSM** (IT Service Management) | *Jira, TheHive* | **The Paperwork.** This is our ticketing system. Every investigation needs a paper trail. |



### My Role as an L1 Analyst
As a Junior (L1) Analyst, I am the **Gatekeeper**.

Depending on the day, I might get zero alerts, or I might get a hundred. Every single one of them could be a false alarm, or it could be the start of a massive data breach.

Here is how the team splits the work:

* **L1 Analyst (Me):** I review the alerts. I separate the "False Positives" (harmless stuff) from the "True Positives" (real threats). If it's a real threat, I ring the alarm.
* **L2 Analyst:** I escalate the real threats to them. They perform the deep dive, forensic analysis, and remediation.
* **SOC Engineer:** They tune the tools. If I'm getting too many false alarms, they fix the code so the alerts are smarter.
* **SOC Manager:** They track the metrics. They ensure we are spotting attacks fast enough (Time to Detect) and fixing them fast enough (Time to Respond).

---
---

## Task 3: Alert Properties — Decoding the Message

![alt text](/THM/SOC%20LEVEL-1/Images/j3_alerts.png)

### Reading the Label
Once an alert actually lands in my queue, it’s not just a blinking light. It’s a file full of data. My mentor told me that before I panic or start clicking things, I need to understand exactly what I'm looking at.

While every SIEM looks different, the "anatomy" of an alert is almost always the same. Here is the checklist I go through for every single ticket:

| Property | What it Means (My Take) | Examples |
| :--- | :--- | :--- |
| **1. Alert Time** | **The Lag.** <br> This shows when the alert was created. *Crucial Note:* There is usually a delay. The bad guy might have acted at 15:32, but the alert popped at 15:35. | *Alert Time: March 21, 15:35* <br> *Event Time: March 21, 15:32* |
| **2. Alert Name** | **The Headline.** <br> This is the summary based on the detection rule. It tells me immediately what kind of fight I'm getting into. | *Unusual Login Location* <br> *Windows RDP Bruteforce* <br> *Potential Data Exfiltration* |
| **3. Alert Severity** | **The Panic Level.** <br> This defines urgency. It's set by the engineers, but I can change it if I find out a "Low" alert is actually a "Critical" disaster. | 🟢 **Low:** Monitor it. <br> 🟡 **Medium:** Investigate soon. <br> 🟠 **High:** Drop everything. <br> 🔴 **Critical:** Wake up the boss. |
| **4. Alert Status** | **The Workflow.** <br> This tells the team if someone is already handling it so we don't double-work. | 🆕 **New:** Nobody has touched it. <br> 🔄 **In Progress:** I'm working on it. <br> ✅ **Closed:** Case closed. |
| **5. Alert Verdict** | **The Judgment.** <br> This is the final stamp I put on the file. Was it a hacker, or just Bob from Accounting forgetting his password? | 🔴 **True Positive:** Real Threat. <br> 🟢 **False Positive:** False Alarm / Noise. |
| **6. Alert Assignee** | **The Owner.** <br> This shows who is responsible. If my name is here, I own the outcome. | *assignee: "j.doe"* |
| **7. Alert Description** | **The Context.** <br> This is the "Why." It explains the logic behind the rule and sometimes gives instructions on how to handle it. | *Explains why this specific activity indicates an attack.* |
| **8. Alert Fields** | **The Clues.** <br> The specific data points I need to investigate. IP addresses, usernames, file hashes. | *Affected Hostname* <br> *Entered Commandline* |

---
---

## Task 4: Alert Prioritization — The Triage

### Controlling the Chaos
Okay, I can now read and understand the alerts. But looking at the dashboard, there are hundreds of them. It feels like standing in an emergency room with fifty patients screaming at once. Who do I help first?

This is called **Alert Prioritization**. It is the most crucial skill I need to learn. If I pick the wrong ticket, I might be fixing a broken window while the house next door burns down.

### My Selection Algorithm
Every SOC team has its own rules (often automated in the SIEM), but my mentor taught me the "Golden Standard" for manual selection. It’s a simple 3-step filter:

#### 1. Filter the Noise (The "Taken" Check)
**Rule:** *Never double-work.*
Before I even look at the threat level, I check the status. Is another analyst already working on this?
* If **Yes**: I skip it.
* If **No** (New/Unassigned): I take it.

#### 2. Sort by Severity (The "Impact" Check)
**Rule:** *Tackle the fire, not the cat in the tree.*
I always sort the list by severity: **Critical > High > Medium > Low**.
* **Why?** Detection engineers design "Critical" rules for a reason. These are highly likely to be real, major threats. A "Critical" alert is usually a confirmed breach, whereas a "Low" alert might just be a typo.

#### 3. Sort by Time (The "Clock" Check)
**Rule:** *Oldest is deadliest.*
This was counter-intuitive to me at first. I thought I should grab the *newest* thing. I was wrong.
* **The Logic:** If I have two Critical alerts—one from 10 minutes ago and one from 10 hours ago—I take the **oldest** one first.
* **Why?** The hacker from the older alert has been inside the network longer. They are closer to stealing data or causing damage. The "newcomer" is likely just starting their reconnaissance.

![alt text](/THM/SOC%20LEVEL-1/Images/j3_alert_process.png)

