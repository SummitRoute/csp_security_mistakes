# Cloud Service Provider security mistakes
This page lists security mistakes by cloud service providers (AWS, GCP, and Azure). These are public mistakes on the cloud providers' side of the shared responsibility model. This may be CVEs or bug bounties for issues in the services they run, but could also be in client software they provide, guidance they have given, failed audit tests in their SOC 2 Type 2, security incidents they have had, and more.  

Whether an issue is included or not is hard to define and thus opinionated.  For my definition of a mistake, I am not including business decisions such as AWS releasing a service before it has Cloudtrail auditing support, or some technical decisions by the cloud providers such as the ease with which an S3 bucket can be made public.  Some technical decisions are concerning enough to be listed here though. I'm avoiding GSuite and Office365 issues. I am not including security incidents at the companies that did not seem to impact the cloud services for customers (ex. when Amazon's Twitch was hacked, it didn't impact AWS customers), or security incidents of their customers (ex. Capital One's breach on AWS).

The purpose of this project is to ensure there is a record of these mistakes. Although I believe using cloud providers is often a much better decision than self-hosting, it's important to hold them accountable by recognizing their security mistakes.

Where possible I also want to ensure customers know what steps they can take to detect or prevent the issues identified.  Mitre, which is the organization that manages CVEs, has generally avoided providing CVEs for security issues of the cloud providers under the assumption that all issues can be resolved by the cloud provider and therefore do not need a tracking number. This view is sometimes incorrect, and even when the issue can be resolved by the cloud provider, I still believe it warrants having a record.  Similar views are expanded on by Alon Schindel and Shir Tamari from Wiz.io in their post [Security industry call to action: we need a cloud vulnerability database](
 https://www.wiz.io/blog/security-industry-call-to-action-we-need-a-cloud-vulnerability-database).

## Field explanations

#### Name: Name of the vulnerability if available, or a short explanation
- Summary: Explanation of the issue
- Platform: cloud provider (AWS, GCP, or Azure)
- Severity: My opinion. This needs to be improved to takes into consideration how potentially widespread this issue was (was it a newly released service or one that has been around for years?), what would be achieved by an attacker abusing this issue (full data compromise?), and whether other issues needed to be chained to this for it to be exploited (did the attacker need privileges in your environment already? Did they need special knowledge of your environment? Did they need a victim to visit a link?).  
- Date: Date this was discovered pr published if unknown. The actual date where this impacted customers may have been much earlier, and the date it was published, or fixed may be much later. This is just to give this list some sort of ordering.
- Discoverer: Individuals who found the issue and where they worked at the time
- Customer action: Whether there is anything a customer could do as follow-up to this issue.
- References: Publication of the research and response from the cloud provider if it exists.

# Issues

### AWS employee posts customer access keys and information
- Summary: AWS employee pushed data to a public github bucket containing AWS access keys and other credentials of customers and their data
- Platform: AWS
- Severity: CRITICAL
- Date: January 13, 2020
- Discoverer: Upguard
- Customer action: Roll impacted credentials
- References: 
  - https://www.upguard.com/breaches/identity-and-access-misstep-how-an-amazon-engineer-exposed-credentials-and-more


### GuardDuty detection bypass via cloudtrail:PutEventSelectors
- Summary: GuardDuty detects CloudTrail being disabled, but did not detect if you filtered out all events from CloudTrail, resulting in defenders having no logs to review. Require privileged access in victim account, resulting in limited visibility.
- Platform: AWS
- Severity: LOW
- Date: April 23, 2020
- Discoverer: Spencer Gietzen, Rhino Security
- Customer action: Setup detections independent of GuardDuty
- References: 
  - https://github.com/RhinoSecurityLabs/Cloud-Security-Research/tree/master/AWS/cloudtrail_guardduty_bypass






### GCP org policies bypass
- Summary: Allows an attacker with privileges in the account to share resources outside of the account even when an org policy restricts this, thus enabling them to backdoor their access.
- Platform: GCP
- Severity: Medium
- Date: May 15, 2021
- Discoverer: Kat Traxler (https://twitter.com/NightmareJS)
- Customer action: N/A
- References: 
  - https://kattraxler.github.io/gcp/hacking/2021/09/10/gcp-org-policy-bypass-ai-notebooks.html


### ChaosDB
- Summary: All CosmosDB customer data compromised. Series of mistakes by Azure shows systemic lack of security best practices.
- Platform: Azure
- Severity: Critical - All customer data for service compromised for service that had been around since 2017
- Date: August 9, 2021
- Discoverer: Nir Ohfeld and Sagi Tzadik, Wiz.io
- Customer action: Regenerate primary read/write key 
- References: 
  - https://chaosdb.wiz.io/
  - https://www.wiz.io/blog/chaosdb-how-we-hacked-thousands-of-azure-customers-databases
  - https://www.wiz.io/blog/chaosdb-explained-azures-cosmos-db-vulnerability-walkthrough


### Azurescape
- Summary: Cross-account container escape
- Platform: Azure
- Severity: Critical
- Date: September 9, 2021
- Discoverer: Yuval Avrahami, Palo Alto
- Customer action: 
- References: 
  - https://unit42.paloaltonetworks.com/azure-container-instances/


### Log analytics role privesc
- Summary: Privilege escalation of Log Analytics Contributor role to Subscription Contributor role.
- Platform: Azure
- Severity: Medium
- Date: September 13, 2021
- Discoverer: Karl Fosaaen, SPI
- Customer action: N/A
- References: 
  - https://www.netspi.com/blog/technical/cloud-penetration-testing/escalating-azure-privileges-with-the-log-analystics-contributor-role/

### OMIGOD
- Summary: Azure forces the install of an agent on Linux VMs, which contained a vuln that would grant root RCE if an attacker could send a web request to them 
- Platform: Azure
- Severity: Critical
- Date: September 14, 2021
- Discoverer: Nir Ohfeld, Wiz.io
- Customer action: N/A, client needed to be auto-updated
- References: 
  - https://www.wiz.io/blog/secret-agent-exposes-azure-customers-to-unauthorized-code-execution


### IAP bypass
- Summary: Convincing a victim to click a specially crafted link would allow the attacker to bypass the Identity-Aware Proxy (a core component of BeyondCorp). 
- Platform: GCP
- Severity: Medium
- Date: September 17, 2021
- Discoverer: Unknown
- Customer action: N/A
- References: 
  - https://cloud.google.com/support/bulletins#gcp-2021-020


### Workspace client RCE - CVE-2021-38112
- Summary: If a user with AWS WorkSpaces 3.0.10-3.1.8 installed visits a page in their web browser with attacker controlled content, the attacker can get zero click RCE under common circumstances.
- Platform: AWS
- Severity: High
- Date: September 21, 2021
- Discoverer: David Yesland, Rhino security
- Customer action: Update client to 3.1.9 or higher
- References: 
  - https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/





