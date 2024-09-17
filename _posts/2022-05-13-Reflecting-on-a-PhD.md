---
title: Reflecting on Completing a PhD
date: 2022-05-13
categories: []
tags: [school]
---
In March of this year, I successfully defended my dissertation [An Application of Machine Learning to Packed Mach-O Detection][1]. After four years, I completed a [PhD in Cyber Operations][2] from Dakota State University (DSU). In this post, I want to reflect on this journey, what I learned, and thoughts on the program.

# Curriculum
The DSU PhD in Cyber Operations consists of core technical classes, core research classes, electives, and the dissertation. When I started the program, it was actually a Doctor of Science (DSc) vice a Doctor of Philosophy, but the South Dakota Board of Regents approved the transition to PhD relatively soon after my acceptance.
## Core Technical Classes
**CSC840: Cyber Operations I**  
CSC840 and its follow-up, CSC841, act as a “survey” of the cyber operations field. In this class, we examined the legal frameworks which underpin how organizations conduct operations, whether those are offensive (such as government hacking) or defensive (such as organizations performing system monitoring). The Border Gateway Protocol was investigated by constructing a virtual autonomous system via multiple pfSense machines and performed BGP prefix hijacking. Next we implemented a network interceptor, similar to FakeNetNG, to proxy malware communications. We also wrote scripts to extract Indicators of Compromise (IOC) from malware files, Yara rules to detect malware, and extracted files from packet captures. We analyzed the Ranbyus Domain Generating Algorithm (DGA), implemented the algorithm ourselves, and wrote regular expressions to detect the DGA domains in DNS logs. Lastly, we developed academic learning objectives, assessments, and curriculum to teach a security concept.

**CSC841: Cyber Operations II**  
CSC841 contains labs using Software Defined Radios (SDR). GNU Radio was used to demodulate captured radio transmissions and we use triangulation of GSM signals to geolocate a signal. We intercepted WiFi signals by setting interfaces into monitor mode and writing scripts to poll the interface, parse frames, and centralize logging in Greylog. We created analytics to hunt in Greylog for deauthorization attacks and to generate statistics for client activity. In another lab, we created a GSM network using OpenBTS, joined Android devices, sent messages between the phones, and analyzed GSM traffic with Wireshark. This course also used Network Intrusion Detection System (NIDS) and Network Address Translation (NAT). We implemented NAT in a language of our choice, created malware that used Command and Control (C2), and wrote NIDS rules to detect the C2 traffic. Lastly, we stood up VPNs using Wireguard.

**CSC844: Reverse Engineering**  
CSC844 was an Internet of Things (IoT) focused Reverse Engineering (RE) course. At the time, the course was under transition from one faculty member to another, and this perhaps led to the course being more free-form than expected. We were to obtain an IoT device, extract firmware, intercept traffic, and RE mobile apps, all in an attempt to find a vulnerability to generate a [Common Vulnerability and Exposure][3] (CVE). I used an Ikea Tradfri hub that I had laying around. Using a [Bus Pirate][4], I pulled firmware off the device’s flash storage and extracted files with binwalk. The extracted files were from an HDR0 filesystem, and executables were ARM. I reverse-tethered my phone to my laptop to intercept traffic between the Ikea app and the device and discovered that the communications were encrypted with dTLS. While I was not able to find any vulnerabilities, I did implement automation of the device with Python using COAP client.

**CSC846: Advanced Malware Analysis**  
CSC846 provided an opportunity to analyze multiple samples of malware. I used this class as a motivation to install Cuckoo in my homelab. We analyzed macro-embedded documents and deobfuscated VBScript, Powershell, Javascript, and PHP. We analyzed PCAPs to identify C2 nodes, exfiltrated data, and follow-on payloads. Exploit kits were analyzed to determine CVEs used and payload functionality. Packed payloads were unpacked, using both tools such as UPX and manually after RE’ing the algorithm. Modular payloads were examined and RE’d to determine functionality. Lastly, reflective injection loaders and payloads were analyzed.

**CSC848: Advanced Software Exploitation**  
CSC848 was focused on defeating exploit mitigations and writing shellcode. We used both Return Oriented Programming (ROP) and Jump Oriented Programming (JOP) to defeat Data Execution Prevention (DEP). We used a memory leak to defeat Address Space Layout Randomization (ASLR). Other techniques included heap spraying, Use After Free (UAF), and Structured Exception Handling (SEH). We also did a small amount of kernel debugging and exploitation.
## Core Research Classes
**CSC803: An Introduction to Cyber Security Research**  
CSC803 was the first class in the research process. It focused on learning about the dissertation process and the structure of a dissertation. We understood our world view and quantitative and qualitative research. We refined our ability to search literature databases and critically read research papers. Problem statements and research questions were generated. This was our first chance to officially begin the dissertation research by conducting a survey of relevant literature and was equivalent to the work involved in Chapter One.

**CSC804: Cyber Security Research Methods**  
CSC804 continued the theme of the dissertation process. The class went deeper into qualitative and quantitative methods, and explored design science. We read papers using each method and practiced applying those methods to our research problems and questions. This work was equivalent to Chapter Two.

**CSC807: Cyber Security Research**  
CSC807 gave practice in defining a research question, conducting a literature review, defining a methodology, conducting research, writing  results, and publishing. The European Union Agency for Cyber Security’s Threat Landscape served as a starting point for identifying an area of research. Throughout the course, we dove into a topic from the report, developed a research question, and worked to answer it. For my topic, I researched DNS over HTTPs and was published in the proceedings of the [International Conference on Information and Computer Technologies][5].
## Electives
Three electives are required. I took additional electives to shore up Machine Learning (ML) skills for my dissertation topic or because I had an interest.

**CSC748: Software Exploitation**  
CSC748 is a recommended elective that teaches software exploitation. It covered buffer overflows, defeating DEP with ROP chains from Mona, and writing shellcode. It was useful as a refresher for these techniques but was not new to me.

**CSC842: Security Tool Development**  
CSC842 is operated as several development sprints. In each sprint, you develop a tool to solve a security problem, alternating every two weeks. On the “off” weeks, you create content to share the tool and what you learned. I used this course to learn more about Mac malware. First I developed a Python script to enumerate [persistence locations on macOS][6]. In a subsequent sprint, I ported the functionality to Swift, my first time using this language. For the last three sprints, I developed and iterated a [malware C2 framework][7] that used a blog post and comments for obfuscated communications.

**CSC722: Machine Learning Fundamentals**  
CSC722 covered the theory and implementation of a few algorithms for machine learning classification. The class used “stock” datasets.

**CSC723: Machine Learning for Cyber Security**  
CSC723 contextualized ML to cyber security problems. We primarily used existing datasets of malware, network traffic, or keystroke timing data for either classification or anomaly detection. As an option to one of the projects for this course, I started gathering macOS malware samples to use for my dissertation.

**INFA720: Incident Response**  
INFA720 introduces the Incident Response (IR) process. Most of the course is from the perspective of a leader of an IR program, with only a few labs with practical application. We developed an IR plan, produced templates, and created table top exercises.
## Dissertation
The dissertation phase begins after completing the core classes and passing the oral comprehensive exams.
**CSC809: Dissertation Preparation**  
CSC809 acts as a guide for preparing Chapters One, Two, and Three for the dissertation and culminates with the proposal. If not already completed, we formed a dissertation committee.

**CSC890: Research Seminar**  
CSC890 is a one-week residency requirement of the program. Three iterations of CSC890 are required. During CSC890, we went onsite to DSU’s campus in Madison, SD. This was a great opportunity to meet the other students, since all other classes are available remote. During the week of CSC890, students present their dissertation proposals and defenses, and conduct oral exams.

**CSC898D: Dissertation**  
CSC898D is the “course” for tracking dissertation progress. 22 credits are required and can be spread across a number of semesters.

My dissertation topic involved applying machine learning to the problem of classifying macOS malware as packed. What I learned most centered on building a dataset for machine learning. In any class where I’ve used ML, the datasets were provided and relatively clean already. Since this was original research, I needed to obtain malware samples, make decisions on balancing the dataset with benign samples, and figure out how to extract features. Once the data was extracted, I had to figure out how to store and load the data and transform it to suitable data types.
# Thoughts on the program
I enjoyed the time that I spent in DSU’s program. There was a good variety in the content of the core courses which either reinforced previously learned ideas or exposed me to new topics that I found interesting. The requirements that I had when searching for a PhD program were: it could be completed part time and was available to remote learning. When researching programs, I found that this one had the most hands-on technical content.

I used the GI Bill to pay for school. DSU’s cost seems reasonable if I had to pay out of pocket. A credit costs roughly $500, and excepting CSC898D and CSC890, courses are three credits. That is $1,500 per course and about a third the cost of some other programs. The cost of travel to South Dakota three times adds about $3,000.

The faculty are in the process of changing the required courses. I neglected to write down the changes, but I thought that they made sense and would streamline the program. If I recall correctly, the independent study and research course (INSuRe) will be required will provide a real-world problem for research.

DSU has some very knowledgable faculty. As always, I “clicked” with some professors more than others. There is some change in the faculty; some professors are leaving for new positions. The school will need to replace them with equally qualified personnel in addition to expanding their ranks. DSU is the third largest school in the state, but is on track to produce the largest number of PhDs in the state. Scaling up to meet that demand could be challenging.

I think the future still looks bright for incoming students. DSU recently established a public-private partnership in SD to build a new research park in Sioux Falls. In addition to the existing Applied Research Labs, there will be ample opportunities to work on cyber security problems across a range of specialities, including IoT, medical devices, and malware. 

[1]:	https://scholar.dsu.edu/theses/381/
[2]:	https://dsu.edu/programs/phdco/index.html
[3]:	https://www.cve.org
[4]:	https://dangerousprototypes.com/docs/Bus_Pirate
[5]:	https://www.researchgate.net/profile/Houssain-Kettani/publication/341406357_On_the_Impact_of_DNS_Over_HTTPS_Paradigm_on_Cyber_Systems/links/5ed7d1ad299bf1c67d359f03/On-the-Impact-of-DNS-Over-HTTPS-Paradigm-on-Cyber-Systems.pdf
[6]:	https://github.com/kimobu/mac_autoruns
[7]:	https://github.com/kimobu/blog-c2