Background - The solvi system is a major and a future shaping energy sector in South Africa At the heart of Solvi Systems' operations is its Docks software, a critical component used by major power and utility companies.

Solvi Systems' influence extends beyond national borders. The company plays a crucial role in regional stability, as South Africa exports power to neighboring states like Mozambique, Eswatini, Zimbabwe, and Namibia. This interconnectedness means that any vulnerability or disruption in South Africa's energy infrastructure, and by extension Solvi Systems' software, doesn't just affect one nation but echoes across the region.

Given this key role, Solvi Systems is a prime target for cyber adversaries. You've been hired to identify any intrusions against this company.
---
Question 2
:   (
10
) points
To start your investigation, you will need access to the company's pool of data!

Login to Azure Data Explorer (ADX). This is where you will find our TOP SECRET data. You will need a Microsoft account (hotmail, outlook, O365..) We will use ADX to run queries that will help us answer these questions.

The training guide will teach you how to answer the KQL101 questions.

Run a take 10 on each of the tables to see what kind of data they contain.

Employees
| take 10
Copy
Anytime you're stuck while trying to write a query, you can always use take 10 to remind yourself what columns and values are in that table!

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/one.png)

---
Section 1: KQL 101
Question 3
:   (
10
) points

Now that we have access to the data, we'll need to get a lay of the land. Let's get some more information about Solvi Systems.

How many employees work at Solvi Systems?

Employees
| count

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/two.png)

---

Section 1: KQL 101
Question 4
:   (
10
) points
We can use the where operator with the Employees table to find a specific employee.

Here is a template you can follow:

Table
| where <field> <operator> <value>
Copy
To learn more about how to use where, see the training guide.

What is the CTO's name?

Employees
| where role == "CTO"

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/3.png)

---
Section 1: KQL 101
Question 5
:   (
10
) points
We can learn more about Alexis Khoza using information from other tables. Let's take her email address from the Employees table and use it in a query for the Email table.

How many emails did Alexis Khoza receive?

Email
| where recipient == "<Alexis Khoza's Email Address Here>"
| count

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/four.png)

---

Section 1: KQL 101
Question 6
:   (
10
) points
You can use the distinct operator to find unique values in a specific column.

How many distinct senders were seen in the email logs from eskom.co.za?

Email
| where sender has "<Domain Name>"
| distinct <field>
| count

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/five.png)

---

Section 1: KQL 101
Question 7
:   (
10
) points
How many distinct websites did “Alexis Khoza” visit?

OutboundNetworkEvents
| where src_ip == "<Alexis Khoza IP>"
| <operator> <field>
| <operator>

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image.png)

---

Question 8
:   (
10
) points
How many distinct domains in the PassiveDns records contain the word “real”?

PassiveDns
| where <field> contains <value>
| <operator> <field>
| <operator>
Copy
You may notice we're using contains instead of has here. If you are curious about the differences between these, check out this post.

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-1.png)

---
Question 9
:   (
10
) points

What IPs did the domain “bit.ly” resolve to (enter any one of them)?

PassiveDns
| where domain == "<domain>"
| distinct <field>

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-2.png)

---

Question 10
:   (
10
) points
How many distinct URLs did employees with the first name "Mary" Visit?

let mary_ips = 
Employees
| where name has "<Employee Name>"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (mary_ips)
<more kql here>

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-3.png)

---

Question 11
:   (
10
) points
How many authentication attempts did we see to the accounts of employees with the first name Mary?

let <list_variable_name> = Employees
| where name has "<Employee Name>"
| distinct username;
AuthenticationEvents
| where username in (<list_variable_name>)
| count

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-4.png)

---

Section 2: Someone's knocking
Question 1
:   (
40
) points
Our mission is to identify any intrusion attempts against Solvi Systems. In order to do this, we'll start by reviewing some alerts.

You got an alert from your Web Application Firewall (WAF) appliance that someone may be trying to compromise your Solvi System's website!

{
   description: "DETECTION RULE TRIGGERED",
   severity: "HIGH",
   rule_description: "SUSPICIOUS TEXT IN HTTP REQUEST",
   data: https://www.solvisystems.com/feedback?message=</script>. 
 <script>alert('xss')</script>
}

---

Question 2
:   (
40
) points
We can actually identify this request in our inbound browsing logs.

InboundNetworkEvents
| where url contains "alert"
Copy
What javascript command was the attacker trying to run?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-5.png)

---

Question 6
:   (
100
) points
Ok, that first attempt was unsuccessful but it may not have been the only one.

Let's look for other malicious requests the attacker could have made around that time. It looks like the attacker varied the ip addresses they used to make these requests.

Use this query as a template:

InboundNetworkEvents
| where user_agent == "<user_agent>"
| where timestamp between (datetime("2024-05-03") .. datetime("2024-05-05"))
Copy
How many malicious requests did the attacker make in total?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-6.png)

---
Question 9 (solved)
:   (
30
) points
It looks like the threat actor did some reconnaissance prior to the attack. They were seen browsing the company website before sending malicious requests to it.

How many total records do we have of them browsing Solvi Systems?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-7.png)

---

Question 12
:   (
40
) points
So we know the web exploitation attempts failed, but surely that couldn't be the end of it. Based on the reconnaissance we saw, these threat actors were far too interested in Solvi Systems to give up that easily.

Let's try pivoting on the adversary infrastructure to see if they tried to get in some other way.

First we'll look in PassiveDns to see if there are any domains registered by the adversary.

How many distinct domains do the ip addresses used by the threat actor resolve to?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-8.png)

---

Hmmm… These domains smell like they were registered for nefarious purposes. Perhaps for…phishing?

Let's check out the email logs to confirm.

Did we receive any emails containing these domains? (yes/no)

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-9.png)

---

Oh no! We received so many malicious emails. They weren't done after all!

Good news: we have new leads in our investigation.
Bad news: we have more investigating to do!

Let's explore these malicious emails that were sent by the adversary.

How many emails associated with these domains did SolviSystem employees receive?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-10.png)

---

Section 3: Snail Mail
Question 2
:   (
60
) points
Before we move on, let's try to get a better scope of the investigation.

You'll answer the following questions about the 56 emails we found earlier that had the adversary domains.

How many distinct email addresses did the threat actor use?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-11.png)

---
Question 3
:   (
50
) points
How many distinct filenames were observed in the links in these emails?


![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-12.png)

---

Question 4
:   (
50
) points
Let's look into the employee roles that this threat actor was targeting.

How many different roles were targeted with these emails?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-13.png)

---

Question 5 (solved)
:   (
50
) points
How many Customer Support Specialist employees received malicious emails?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-14.png)

---

Question 6
:   (
60
) points
Among these job roles, which word is shared by three of them?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-15.png)

---
Question 7 (solved)
:   (
40
) points
We can't investigate all of the emails at once so we'll start by looking in detail at one of the emails.

What was the timestamp of the first email the threat actor sent?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-16.png)

---

Question 14
:   (
40
) points
Did Carla click on the link in email? If so when?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-17.png)
---

Question 15
:   (
40
) points
What file was observed on Carla's machine shortly after she executed the docx file?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-18.png)

---

Section 4: Ecoshock
Question 1 (solved)
:   (
40
) points
How many records do we have of this file being created on Solvi Systems computers?

 39

 ![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-19.png)


---

Let's go back and look at the process events on Carla's machine to see what happens after ecobug.exe is created.

What IP address does ecobug.exe connect to in order to establish persistence?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-20.png)

---

Question 4
:   (
50
) points
We can now examine the NetworkFlow data to observe the persistent connection.

How many times does Carla's machine connect to the suspicious IP address

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-21.png)

---
How many distinct employee machines are involved in those connections?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-22.png)

---
Question 9 (solved)
:   (
60
) points
We've gained some pretty good information on how the malware communicated with the threat actor's infrastructure. Let's go back to the malware to see what actions it performed on the victims' machines.

A day after the malware is first executed the threat actor attempts to create a new user and add that user to the local administrators group.

What is the name of the newly created user?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-23.png)

---

Question 11 (solved)
:   (
60
) points
After the malware was executed on Carla's machine, a series of commands were run relating to reconnaissance on the compromised system.

We can find these discovery commands.

What was the last discovery command that the adversaries ran?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-24.png)

---

Looks like we hit a dead end. The threat actors didn't seem interested enough to do anything else on Carla's machine.

We can use this as an anchor point though. Perhaps the threat actor is a creature of habit.

How many distinct commands containing the term net use were run on SolviSystem devices?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-25.png)

---

Question 3 (solved)
:   (
70
) points
Let's investigate the use of net use /PERSISTENT:YES further.

How many distinct hosts was this command run on?

 ![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-26.png)

---


Question 8 (solved)
:   (
70
) points
Now let's go back and see if there were other commands run on Alexei's machine after net use /PERSISTENT:YES.

It looks like the adversary was copying files from a network share onto Alexei's machine.

What is the command used to copy files related to SoftwareDevelopment?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-27.png)

---

Question 9
:   (
70
) points
After collecting the sensentive data, the adversary compressed it and moved it to another location.

What is the name of the archive file containing the copied documents?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-28.png)

---

Question 12
:   (
150
) points
The adversaries appeared to be highly invested in learning more about Solvi's software development process. Perhaps they want to be better understand Solvi's code bases, or figure out how to inject their own malicious code in Solvi's software.

Around the same time the adversaries stole data from the network share about the software lifecycle, they were also seen accessing sensitive documents about the software lifecycle.

The threat actors were observed reading an "internal process" document from an internal portal called ____.solvisystems.com

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-29.png)

---

The adversaries also tried going an unconventional route and simply asking nicely 🤣 for details about the SDLC using the compromised user's accounts.

These compromised users sent a few emails prodding for information about the location of important software documentation.

What was the subject of those emails?

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-30.png)

---

![alt text](/K7cyber_Walkthrough/Solvi's_system_SS/image-31.png)