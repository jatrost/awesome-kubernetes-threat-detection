# Awesome Kubernetes (K8s) Threat Detection [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

A curated list of resources about detecting threats and defending Kubernetes systems.

# Contents

- [📚 Books](#books)
- [🏫 Conferences](#conferences)
- [📹 Talks and Videos](#talks-and-videos)
- [📰 Blogs and Articles](#blogs-and-articles)
- [🧮 TTPs / Attack Matrices](#ttps--attack-matrices)
- [🛠 Tools](#tools)
- [🔍 Detection Rules and Analytics](#detection-rules-and-analytics)
- [🤖 People](#people)

## Books

* [Hacking Kubernetes](https://learning.oreilly.com/library/view/hacking-kubernetes/9781492081722/) By Andrew Martin, Michael Hausenblas [[free download](https://control-plane.io/hackingkubernetes/)] [[amazon](https://amzn.to/3msjXDH)]
* [Kubernetes Security and Observability](https://learning.oreilly.com/library/view/-/9781098107093/) by Brendan Creane, Amit Gupta [[amazon](https://amzn.to/3mt21sh)]
* [Security Observability with eBPF](https://learning.oreilly.com/library/view/security-observability-with/9781492096719/) by Jed Salazar and Natalia Reka Ivanko
* Gray Hat Hacking, 6th Ed. (relevant chapters) By Allen Harper, Ryan Linn, Stephen Sims, Michael Baucom, Huascar Tejeda, Daniel Fernandez, Moses Frost [[amazon](https://amzn.to/41FZXO5)]
  * [Ch 29. Hacking on Containers](https://learning.oreilly.com/library/view/gray-hat-hacking/9781264268955/p29.xhtml) [[Ch 29 Labs](https://github.com/GrayHatHacking/GHHv6/tree/main/ch29)]
  * [Ch 30. Hacking on Kubernetes](https://learning.oreilly.com/library/view/gray-hat-hacking/9781264268955/p30.xhtml) [[Ch 30 Labs](https://github.com/GrayHatHacking/GHHv6/tree/main/ch30)]
* [Kubernetes Patterns, 2nd Edition, Part 5: Security Patterns](https://learning.oreilly.com/library/view/kubernetes-patterns-2nd/9781098131678/part05.html) by Bilgin Ibryam and Roland Huss [[amazon](https://amzn.to/3ZnIckR)]
* [Container Security Book](https://learning.oreilly.com/library/view/-/9781492056690/) by Liz Rice [[amazon](https://amzn.to/3ZnIckR)]

## Conferences

* eBPF Summit [[2022](https://ebpf.io/summit-2022.html)] [[2021](https://ebpf.io/summit-2021.html)] [[2020](https://ebpf.io/summit-2020.html)]
* [CloudNative SecurityCon](https://events.linuxfoundation.org/cloudnativesecuritycon-north-america/)

## Talks and videos

All of these videos can also be found in this [YouTube playlist](https://www.youtube.com/playlist?list=PL5ZaBJnKnwWxecVvTc0cWMu-GDdB1i8dh).

### Detection

* [Keynote: Detecting Threats in GitHub with Falco](https://www.youtube.com/watch?v=o3Mz3ha3gMM) 
* [Threat Hunting at Scale: Auditing Thousands of Clusters With Falco](https://www.youtube.com/watch?v=OyB0TWVjZvY&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=6) 
* [Security Kill Chain Stages in a 100k+ Daily Container Environment with Falco](https://www.youtube.com/watch?v=L-5RYBTV010) 
* [Falco to Pluginfinity and Beyond](https://www.youtube.com/watch?v=tZI8Tzf1uzg&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=232) 
* [Purple Teaming Like Sky’s the Limit – Adversary Emulation in the Cloud](https://www.youtube.com/watch?v=hDJpU4Eh1ms) 
* [Uncovering a Sophisticated Kubernetes Attack in Real Time Part II.](https://www.oreilly.com/library/view/infrastructure-ops/0636920625377/video335775.html)
* [Keeping your cluster safe from attacks with eBPF](https://www.youtube.com/watch?v=agN68U8x1go)
* [Threat Modeling Kubernetes: A Lightspeed Introduction](https://www.youtube.com/watch?v=gkXoYFKqQkE&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=184)

### Hardening

* [Securing Kubernetes Applications by Crafting Custom Seccomp Profiles](https://www.youtube.com/watch?v=alx38YdvvzA&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=14) 
* [The Hitchhiker's Guide to Pod Security](https://www.youtube.com/watch?v=gcz5VsvOYmI&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=236) 
* [You and Your Security Profiles; Generating Security Policies with the Help of eBPF](https://www.youtube.com/watch?v=EhQI1qPVb0E)
* [Using the EBPF Superpowers To Generate Kubernetes Security Policies](https://m.youtube.com/watch?v=3dysej_Ydcw)
* [Komrade: an Open-Source Security Chaos Engineering (SCE) Tool for](https://www.youtube.com/watch?v=9uzexriaXj4&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=47) 

### Attacks

* [Advanced Persistence Threats: The Future of Kubernetes Attacks](https://www.youtube.com/watch?v=auUgVullAWM&t=2s) 
* [Bypassing Falco: How to Compromise a Cluster without Tripping the SOC](https://www.youtube.com/watch?v=2rSiSpaR6bI&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=32) 
* [A Treasure Map of Hacking (and Defending) Kubernetes](https://www.youtube.com/watch?v=1HbwfpE4XKY&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=65) 
* [How Attackers Use Exposed Prometheus Server to Exploit](https://www.youtube.com/watch?v=5cbbm_L6n7w&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=235) 
* [Trampoline Pods: Node to Admin PrivEsc Built Into Popular K8s Plat](https://www.youtube.com/watch?v=PGsJ4QTlKlQ&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=234) 
* [Three Surprising K8s Networking “Features” and How to Defend Against Them](https://www.youtube.com/watch?v=7iwnwbbmxqQ&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=118) 
* [A Compendium of Container Escapes](https://www.youtube.com/watch?v=BQlqita2D2s)
* [The Path Less Traveled: Abusing Kubernetes Defaults](https://m.youtube.com/watch?v=HmoVSmTIOxM)

### Supply Chain

* [Securing Your Container Native Supply Chain with SLSA, Github and Te](https://www.youtube.com/watch?v=iZpFtalj4xE&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=12) 
* [Keynote: Securing Shopify's Software Supply Chain - Shane Lawrence, Shopify](https://www.youtube.com/watch?v=yuDMsB0jsdE&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=99) 

### Networking

* [Kubernetes Networking 101 (1h26m)](https://www.youtube.com/watch?v=cUGXu2tiZMc&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=79) 
* [A Guided Tour of Cilium Service Mesh](https://www.youtube.com/watch?v=e10kDBEsZw4&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=76) 
* [Cilium: Welcome, Vision and Updates](https://www.youtube.com/watch?v=oXpGYrbmnwQ&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=181)
* [Cloud-Native Building Blocks: An Interactive Envoy Proxy Workshop (1h25m)](https://www.youtube.com/watch?v=SNM-wnyRR8U&list=PLj6h78yzYM2MCEgkd8zH0vJWF7jdQ-GRR&index=154)

## Blogs and Articles

### Detection

* [Detecting a Container Escape with Cilium and eBPF](https://isovalent.com/blog/post/2021-11-container-escape)
* [Detecting and Blocking log4shell with Isovalent Cilium Enterprise](https://isovalent.com/blog/post/2021-12-log4shell)
* [Threat Hunting with Kubernetes Audit Logs](https://developer.squareup.com/blog/threat-hunting-with-kubernetes-audit-logs/)
* [Threat Hunting with Kubernetes Audit Logs - Part 2](https://developer.squareup.com/blog/threat-hunting-with-kubernetes-audit-logs-part-2/)
* [Lateral movement risks in the cloud and how to prevent them – Part 2: from compromised container to cloud takeover](https://www.wiz.io/blog/lateral-movement-risks-in-the-cloud-and-how-to-prevent-them-part-2-from-k8s-clust)
* [Lateral movement risks in the cloud and how to prevent them – Part 3: from compromised cloud resource to Kubernetes cluster takeover](https://www.wiz.io/blog/lateral-movement-risks-in-the-cloud-and-how-to-prevent-them-part-3-from-compromis)
* [Dive into BPF: a list of reading material](https://qmonnet.github.io/whirl-offload/2016/09/01/dive-into-bpf/)
* [Deep Dive into Real-World Kubernetes Threats](https://research.nccgroup.com/2020/02/12/command-and-kubectl-talk-follow-up/)
* [Understanding Docker container escapes](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [Consider All Microservices Vulnerable — And Monitor Their Behavior](https://kubernetes.io/blog/2023/01/20/security-behavior-analysis/)
* [K8 Audit Logs](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
* [Kubernetes Hunting & Visibility](https://www.lares.com/blog/kubernetes-hunting-visibility/)
* [SCARLETEEL: Operation leveraging Terraform, Kubernetes, and AWS for data theft](https://sysdig.com/blog/cloud-breach-terraform-data-theft/)
* [Detecting Cryptomining Attacks in the wild](https://sysdig.com/blog/detecting-cryptomining-attacks-in-the-wild/)
* [Threat Alert: Kinsing Malware Attacks Targeting Container Environments](https://blog.aquasec.com/threat-alert-kinsing-malware-container-vulnerability)
* [TeamTNT Actively Enumerating Cloud Environments to Infiltrate Organizations](https://unit42.paloaltonetworks.com/teamtnt-operations-cloud-environments/)
* [TeamTNT Targeting AWS, Alibaba](https://blog.talosintelligence.com/teamtnt-targeting-aws-alibaba-2/)
* [Hildegard: New TeamTNT Cryptojacking Malware Targeting Kubernetes](https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/)
* [Siloscape: First Known Malware Targeting Windows Containers to Compromise Cloud Environments](https://unit42.paloaltonetworks.com/siloscape/)
* [CrowdStrike Discovers First-Ever Dero Cryptojacking Campaign Targeting Kubernetes](https://www.crowdstrike.com/blog/crowdstrike-discovers-first-ever-dero-cryptojacking-campaign-targeting-kubernetes/)

### Hardening

* [NSA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
* [Securing Kubernetes Clusters by Eliminating Risky Permissions](https://www.cyberark.com/threat-research-blog/securing-kubernetes-clusters-by-eliminating-risky-permissions/)
* [Container security fundamentals: Exploring containers as processes](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-1/)
* [Container security fundamentals part 2: Isolation & namespaces](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-2/)
* [Kubernetes Security Checklist](https://kubernetes.io/docs/concepts/security/security-checklist/)
* [Under-documented Kubernetes Security Tips](https://www.macchaffee.com/blog/2022/k8s-under-documented-security-tips/)

### Attacks

* [Attacker persistence in Kubernetes using the TokenRequest API: Overview, detection, and prevention](https://securitylabs.datadoghq.com/articles/kubernetes-tokenrequest-api/) 
* [Tetragone: A Lesson in Security Fundamentals](https://grsecurity.net/tetragone_a_lesson_in_security_fundamentals) 
* [How I Hacked Play-with-Docker and Remotely Ran Code on the Host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)
* [The Route to Root: Container Escape Using Kernel Exploitation](https://www.cyberark.com/resources/threat-research-blog/the-route-to-root-container-escape-using-kernel-exploitation)
* [(twitter thread)Quick and dirty way to get out of a privileged k8s pod or docker container by using cgroups release_agent feature.](https://twitter.com/_fel1x/status/1151487051986087936?s=61&t=PSSblCulQVddrn-KweAbhQ)
* [Bad Pods: Kubernetes Pod Privilege Escalation](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation) [[code/examples](https://github.com/BishopFox/badPods)]
* [Kernel privilege escalation: how Kubernetes container isolation impacts privilege escalation attacks](https://snyk.io/blog/kernel-privilege-escalation/)
* [GKE Kubelet TLS Bootstrap Privilege Escalation](https://rhinosecuritylabs.com/cloud-security/kubelet-tls-bootstrap-privilege-escalation/)


## TTPs / Attack Matrices

* [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)
* [Threat matrix for Kubernetes](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/) 
* [Secure containerized environments with updated threat matrix for Kubernetes](https://www.microsoft.com/en-us/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/)
* [OWASP Kubernetes Top 10](https://owasp.org/www-project-kubernetes-top-ten/)
* [OWASP Kubernetes Top 10 (Sysdig)](https://sysdig.com/blog/top-owasp-kubernetes/)
* [AVOLENS Kubernetes Threat Matrix](https://kubernetes-security.de/en/kubernetes_threat_matrix/#kubernetes-threat-matrix)

## Tools

### Detection

* [falco](https://github.com/falcosecurity/falco)
* [tetragon](https://github.com/cilium/tetragon)
* [sysdig](https://github.com/draios/sysdig)
* [tracee](https://github.com/aquasecurity/tracee)
* [security-guard](https://github.com/knative-sandbox/security-guard)

### Hardening

* [seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/) - "can be used to sandbox the privileges of a process, restricting the calls it is able to make from userspace into the kernel."
* [AppArmor](https://kubernetes.io/docs/tutorials/security/apparmor/) - "AppArmor is a Linux kernel security module that supplements the standard Linux user and group based permissions to confine programs to a limited set of resources. AppArmor can be configured for any application to reduce its potential attack surface and provide greater in-depth defense."
* [Kubernetes Network Policy Recipes](https://github.com/ahmetb/kubernetes-network-policy-recipes)

### Simulation / Experimentation

* [Stratus Red Team](https://github.com/DataDog/stratus-red-team) - Stratus Red Team is "Atomic Red Team™" for the cloud, allowing to emulate offensive attack techniques in a granular and self-contained manner.
  * see [Kubernetes Attacks](https://github.com/DataDog/stratus-red-team/blob/main/docs/attack-techniques/kubernetes/index.md)
* [falcosecurity/event-generator](https://github.com/falcosecurity/event-generator)
* [minikube](https://github.com/kubernetes/minikube) - minikube implements a local Kubernetes cluster on macOS, Linux, and Windows. minikube's primary goals are to be the best tool for local Kubernetes application development and to support all Kubernetes features that fit.
* [controlplaneio/simulator](https://github.com/controlplaneio/simulator)
* [kubernetes-goat](https://github.com/madhuakula/kubernetes-goat)
* [Sock Shop: A Microservices Demo Application](https://microservices-demo.github.io/)

### Attack

* [kubesploit](https://github.com/cyberark/kubesploit)
* [Falco-bypasses](https://github.com/blackberry/Falco-bypasses)
* [go-pillage-registries](https://github.com/nccgroup/go-pillage-registries)
* [ConMachi](https://github.com/nccgroup/ConMachi)
* [peirates](https://github.com/inguardians/peirates)
* [botb](https://github.com/brompwnie/botb)
* [kubernetes-info.nse script](https://gist.github.com/jpts/5d23bfd9b8cc08e32a3591c8195482a8)
* [kube-hunter](https://github.com/aquasecurity/kube-hunter)

### Misc

* [kube-iptables-tailer](https://github.com/box/kube-iptables-tailer)
* [inspektor-gadget](https://github.com/inspektor-gadget/inspektor-gadget)


## Detection Rules and Analytics

* [Elastic kubernetes detection rules ](https://github.com/elastic/detection-rules/tree/main/rules/integrations/kubernetes)
* [Falco Rules](https://github.com/falcosecurity/rules)
* [Panther Labs gcp_k8s_rules](https://github.com/panther-labs/panther-analysis/tree/master/rules/gcp_k8s_rules)
* [Sigma cloud/azure/kube*.yml](https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/azure)
* [Sigma cloud/gcp/kube*.yml](https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/gcp)
* [Splunk Analytic Story: Kubernetes Scanning Activity](https://research.splunk.com/stories/kubernetes_scanning_activity/) 
* [Splunk Analytic Story: Kubernetes Sensitive Object Access Activity](https://research.splunk.com/stories/kubernetes_sensitive_object_access_activity/) 
* [Tracee Signatures](https://github.com/aquasecurity/tracee/tree/main/signatures)
* Projectdiscovery/nuclei-templates 
  * [technologies/kubernetes](https://github.com/projectdiscovery/nuclei-templates/tree/main/technologies/kubernetes)
  * [exposed-panels/kube*.yaml](https://github.com/projectdiscovery/nuclei-templates/tree/main/exposed-panels)
  * [misconfiguration/kubernetes](https://github.com/projectdiscovery/nuclei-templates/tree/main/misconfiguration/kubernetes)
  * [exposures/configs/kube*.yaml](https://github.com/projectdiscovery/nuclei-templates/tree/main/exposures/configs)

## People

All the twitter accounts below are on this Twitter list: [awesome-k8-threat-detect](https://twitter.com/i/lists/1632421444347895808)

* [@_fel1x](https://twitter.com/_fel1x)
* [@Antonlovesdnb](https://twitter.com/Antonlovesdnb)
* [@bibryam](https://twitter.com/bibryam)
* [@bradgeesaman](https://twitter.com/bradgeesaman)
* [@christophetd](https://twitter.com/christophetd)
* [@g3rzi](https://twitter.com/g3rzi)
* [@htejeda](https://twitter.com/htejeda)
* [@iancoldwater](https://twitter.com/iancoldwater)
* [@jrfastab](https://twitter.com/jrfastab)
* [@LachlanEvenson](https://twitter.com/LachlanEvenson)
* [@lizrice](https://twitter.com/lizrice)
* [@mhausenblas](https://twitter.com/mhausenblas)
* [@mhausenblas](https://twitter.com/mhausenblas)
* [@mosesrenegade](https://twitter.com/mosesrenegade)
* [@nataliaivanko](https://twitter.com/nataliaivanko)
* [@raesene](https://twitter.com/raesene)
* [@ramesh-ramani](https://www.linkedin.com/in/ramesh-ramani-08bb6b16/)
* [@randyabernethy](https://twitter.com/randyabernethy)
* [@saschagrunert](https://twitter.com/saschagrunert)
* [@sethsec](https://twitter.com/sethsec)
* [@shaul-ben-hai](https://www.linkedin.com/in/shaul-ben-hai-b1609863/)
* [@sshaybbc](https://twitter.com/sshaybbc)
* [@Steph3nSims](https://twitter.com/Steph3nSims)
* [@sublimino](https://twitter.com/sublimino)
* [@sussurro](https://twitter.com/sussurro)
* [@sys_call](https://twitter.com/sys_call)
* [@tgraf__](https://twitter.com/tgraf__)
* [@tixxdz](https://twitter.com/tixxdz)
* [@tpapagian](https://github.com/tpapagian)
* [@willfindlay](https://github.com/willfindlay)
* [@yuvalavra](https://twitter.com/yuvalavra)
* [@jimmesta](https://twitter.com/jimmesta)
