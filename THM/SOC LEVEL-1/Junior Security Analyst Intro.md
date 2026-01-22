# TryHackMe: Junior Security Analyst Journey

## Task 1: Junior Security Analyst Journey

### Why do we need Cybersecurity?
When entering the field of cybersecurity, everyone asks: "Do we really need this?" 

The answer is a simple **yes**. However, we don't need it for the reasons pop culture suggests. It isn't about the "cool stuff" we see in movies or shows like *Asur*, where a hacker types on a green terminal, adds two numbers, and suddenly NASA is hacked. Real security is not a magic trick.

**We need cybersecurity because:**
* The world is evolving and digitizing rapidly.
* Personal details, company secrets, and confidential files are all accessible online.
* **The Trade-off:** While the internet provides easy access to information, it also allows bad actors to read or modify that data. 

Cybersecurity is the necessary shield that protects our digital lives in an interconnected world.

---

### The Role: Junior Security Analyst (SOC Level 1)
*Based on the TryHackMe curriculum.*

A Junior Security Analyst acts as the first line of defense. Working within a Security Operations Center (SOC), the role is often 24/7 and involves constant vigilance.

**Key Daily Duties:**
1.  **Monitoring & Investigation:** Reviewing security alerts to separate false alarms from real threats.
2.  **Collaboration:** Participating in SOC brainstorms and workshops to solve complex problems.
3.  **Defense:** Cooperating with other teams to maintain company safety.
4.  **Continuous Learning:** Keeping up to date with new vulnerabilities (like those found in *The Hacker News*) and evolving defense strategies.

> **Takeaway:** Being an analyst is about analyzing attacks to stop breaches before they hit the news. It is a cycle of monitoring, detecting, and responding.

---
---

## Task 2: Security Operations Center (SOC)

### It's a Team Sport
One thing I realized quickly is that I am not alone in this. Securing a whole company sounds like a massive burden for one person, but that’s where the **SOC (Security Operations Center)** comes in. It is a big machine, and I am just one distinct part of it.

I have a whole squad backing me up, and each person plays a specific role in keeping the ship afloat. Here is who I’ll be working with:

### Meet My Colleagues

* **The Mentor: Suresh (Senior Analyst)**
    * *My relationship with him:* Suresh is my go-to guy. As a Junior, I handle the initial analysis, but when things get confusing or too complex, I escalate it to him. He’s the one who guides me so I don’t mess up.
    
* **The Architect: Smith (SOC Engineer)**
    * *My relationship with him:* I don't see Smith on shift work. Instead, he’s the one building and maintaining the tools I use. If my alerts are configured correctly and my dashboard makes sense, it's thanks to him.

* **The Leader: Sui (SOC Manager)**
    * *My relationship with her:* She keeps the chaos under control. While I look at screens, she deals with the business side—reporting to top management and ensuring the team has what it needs to survive the stress.

* **The Special Forces: Nik (Incident Responder)**
    * *My relationship with him:* Honestly? If I see Nik, I know something bad has happened. He is the heavy hitter called in for major disasters. I don't work with him daily, but he steps in when the house is on fire.

---

### The Path Ahead: Leveling Up
Right now, my goal is to master the basics as a Junior Analyst. But seeing this team inspires me. I realized that cybersecurity isn't just one job; it's a ladder.

**My current mission involves:**
1.  **Defense:** Stopping data stealers on laptops or blocking phishing emails targeting finance.
2.  **Response:** Assisting in major events like ransomware attacks.
3.  **Growth:** working with the team to write better detection rules.

Eventually, I won't just be looking at alerts; I'll be understanding how the whole business breathes and operates.

---
---

## Task 3: A Day in the Life of a Security Analyst

![alt text](/THM/SOC%20LEVEL-1/Images/j1_Task3.png)

![alt text](/THM/SOC%20LEVEL-1/Images/j1_Task3_Flag.png)

---

## Practical Exercise - First Day on the Job

After meeting the team and understanding the theory, it was time to get my hands dirty. In this task, I simulated a real shift to handle my first security incident.

### The Incident
I monitored the security dashboard and investigated a specific alert. By analyzing the logs, I identified a suspicious connection attempting to breach our network.

* **The Malicious Indicator:** `221.181.185.159`

### The Response
As a Junior Analyst, my job isn't just to click buttons but to follow protocol. 
1.  **Escalation:** I didn't act alone. I escalated the alert to **Will Griffin**, the Senior Analyst (my mentor), to confirm my findings.
2.  **Remediation:** Once confirmed, I took action to stop the threat. I accessed the Firewall Management console and blocked the malicious IP address.

### Outcome
The attack was stopped, and the network was secured.

> **Flag Obtained:** `THM{until-we-meet-again}`