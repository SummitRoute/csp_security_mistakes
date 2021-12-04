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
- Severity: My opinion of how bad this is, in relation to other issues on this page.
- Date: Date this was discovered or published if unknown. The actual date where this impacted customers may have been much earlier, and the date it was published, or fixed may be much later. This is just to give this list some sort of ordering.
- Discoverer: Individuals who found the issue and where they worked at the time
- Customer action: Whether there is anything a customer could do as follow-up to this issue.
- References: Publication of the research and response from the cloud provider if it exists.

# Issues

### Launching EC2s did not require specifying AMI owner: CVE-2018-15869
- Summary: Attackers had put malicious AMIs in the marketplace
- Platform: AWS
- Severity: Medium
- Date: January 13, 2020
- Discoverer: Megan Marsh (https://github.com/SwampDragons)
- Customer action: Update CLI and other tools that create EC2s
- References: 
  - https://github.com/hashicorp/packer/issues/6584

### AWS employee posts customer access keys and information
- Summary: AWS employee pushed data to a public github bucket containing AWS access keys and other credentials of customers and their data
- Platform: AWS
- Severity: Critical
- Date: January 13, 2020
- Discoverer: Upguard
- Customer action: Roll impacted credentials
- References: 
  - https://www.upguard.com/breaches/identity-and-access-misstep-how-an-amazon-engineer-exposed-credentials-and-more


### GuardDuty detection bypass via cloudtrail:PutEventSelectors
- Summary: GuardDuty detects CloudTrail being disabled, but did not detect if you filtered out all events from CloudTrail, resulting in defenders having no logs to review. Require privileged access in victim account, resulting in limited visibility.
- Platform: AWS
- Severity: Low
- Date: April 23, 2020
- Discoverer: Spencer Gietzen, Rhino Security
- Customer action: Setup detections independent of GuardDuty
- References: 
  - https://github.com/RhinoSecurityLabs/Cloud-Security-Research/tree/master/AWS/cloudtrail_guardduty_bypass

### Lack of bug bounty
- Summary: Amazon goes public with their HackerOne bug bounty program but excludes AWS
- Platform: AWS
- Severity: Low
- Date: April 22, 2020
- Discoverer: Spencer Gietzen, Rhino Security
- Customer action: N/A
- References: 
  - https://twitter.com/SpenGietz/status/1252971138352701442

### Lack of internal change controls for IAM managed policies
- Summary: Repeated examples of AWS releasing or changing IAM policies they obviously shouldn't have (CheesepuffsServiceRolePolicy, AWSServiceRoleForThorInternalDevPolicy, AWSCodeArtifactReadOnlyAccess.json, AmazonCirrusGammaRoleForInstaller). The worst being the ReadOnlyAccess policy having almost all privileges removed and unexpected ones added.
- Platform: AWS
- Severity: Low
- Date: October 15, 2020
- Discoverer: Aidan Steele
- Customer action: N/A
- References: 
  - https://twitter.com/__steele/status/1316909785607012352


### AssumeRole vendor issues with confused deputy
- Summary: Kesten identifies that you may be able to access other AWS customers through their vendors
- Platform: AWS
- Severity: Medium
- Date: June 12, 2020
- Discoverer: Kesten Broughton, Praetorian
- Customer action: Audit your vendor roles
- References: 
  - https://www.praetorian.com/blog/aws-iam-assume-role-vulnerabilities/


### VPC Hosted Zones unauditable
- Summary: For 6 years, it was not possible to see what hosted zones an attacker may have created in an account.
- Platform: AWS
- Severity: Low
- Date: June 18, 2020
- Discoverer: Aidan Steele
- Customer action: Audit your VPC hosted zones
- References: 
  - https://twitter.com/__steele/status/1273748905826455552

### XSS on EC2 web console
- Summary: Display of EC2 tags had XSS
- Platform: AWS
- Severity: Low
- Date: July 1, 2020
- Discoverer: Johann Rehberger
- Customer action: N/A
- References: 
  - https://embracethered.com/blog/posts/2020/aws-xss-cross-site-scripting-vulnerability/

### Terms and conditions allows sharing customer data
- Summary: Use of the AI services on AWS allows customer data to be moved outside of the regions it is used in and potentially shared with third-parties.
- Platform: AWS
- Severity: Medium
- Date: July 8, 2020
- Discoverer: Ben Bridts
- Customer action: Opt out via Organization AI opt-out policy: https://summitroute.com/blog/2021/01/06/opting_out_of_aws_ai_data_usage/
- References: 
  - https://twitter.com/benbridts/status/1280934515305824256

### S3 Crypto SDK vulns: CVE-2020-8912 and CVE-2020-8911
- Summary: 
- Platform: AWS
- Severity: Low
- Date: July 1, 2020
- Discoverer: Sophie Schmieg, Google
- Customer action: Update SDK
- References: 
  - https://twitter.com/SchmiegSophie/status/1292930639772004352
  - https://github.com/google/security-research/security/advisories/GHSA-76wf-9vgp-pj7w
  - https://github.com/google/security-research/security/advisories/GHSA-f5pg-7wfw-84q9
  - https://github.com/google/security-research/security/advisories/GHSA-7f33-f4f5-xwgw
  - https://aws.amazon.com/blogs/developer/updates-to-the-amazon-s3-encryption-client/

### ALB HTTP request smuggling
- Summary: ALBs found vulnerable to HTTP request smuggling (desync attack).
- Platform: AWS
- Severity: Medium
- Date: October 4, 2019
- Discoverer: Arkadiy Tetelman (https://twitter.com/arkadiyt), Chime; original issue by James Kettle (https://twitter.com/albinowax), Portswigger
- Customer action: Configure setting on your ALBs
- References: 
  - https://twitter.com/arkadiyt/status/1180174359840862209
  - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#load-balancer-attributes

### Execution in CloudFormation service account
- Summary: Ability to run arbitrary Lambda code in an AWS managed account, with privileges to access some data of other customer accounts
- Platform: AWS
- Severity: Critical
- Date: August 26, 2020
- Discoverer: Aidan Steele (https://twitter.com/__steele) and Ian Mckay (https://twitter.com/iann0036)
- Customer action: N/A
- References: 
  - https://onecloudplease.com/blog/security-september-cataclysms-in-the-cloud-formations


### CloudFormer review
- Summary: Audit of AWS open-source project identifies so many issues AWS takes it down
- Platform: AWS
- Severity: Low
- Date: September 25, 2020
- Discoverer: Karim El-Melhaoui (https://twitter.com/KarimMelhaoui)
- Customer action: N/A
- References: 
  - https://blog.karims.cloud/2020/09/25/cloudformer-review-part-1.html

###  AWS Encryption SDK issues
- Summary: 
- Platform: AWS
- Severity: Low
- Date: September 28, 2020
- Discoverer: Thái "thaidn" Dương (https://twitter.com/XorNinja), Google
- Customer action: Update SDK
- References: 
  - https://twitter.com/XorNinja/status/1310587707605659649
  - https://vnhacker.blogspot.com/2020/09/advisory-security-issues-in-aws-kms-and.html


### S3 bucket tagging not restricted
- Summary: Lack of the privilege s3:PutBucketTagging did not restrict the ability to tag S3 buckets
- Platform: AWS
- Severity: Low
- Date: September 28, 2020
- Discoverer:  Ian Mckay (https://twitter.com/iann0036)
- Customer action: N/A
- References: 
  - https://onecloudplease.com/blog/security-september-still-early-days-for-abac


### Identification of privileges without being logged by CloudTrail 
- Summary: An attacker could figure out what privileges they have in a victim account, without being logged in CloudTrail. It took AWS over 273 days to fix this.
- Platform: AWS
- Severity: Low
- Date: September 2, 2020
- Discoverer:  Nick Frichette (https://twitter.com/Frichette_n)
- Customer action: N/A
- References: 
  - https://frichetten.com/blog/aws-api-enum-vuln/
  - https://github.com/Frichetten/aws_stealth_perm_enum


### Fall 2020, SOC 2 Type 2 failure
- Summary: Information is under NDA, but anyone with an AWS account can read it on page 120 and 121.
- Platform: AWS
- Severity: Low
- Date: December 22, 2020
- Discoverer:  Scott Piper 
- Customer action: N/A
- References: 
  - https://twitter.com/awswhatsnew/status/1341461386983952384



### GCP org policies bypass
- Summary: Allows an attacker with privileges in the account to share resources outside of the account even when an org policy restricts this, thus enabling them to backdoor their access.
- Platform: GCP
- Severity: Medium
- Date: May 15, 2021
- Discoverer: Kat Traxler (https://twitter.com/NightmareJS)
- Customer action: N/A
- References: 
  - https://kattraxler.github.io/gcp/hacking/2021/09/10/gcp-org-policy-bypass-ai-notebooks.html


### Lightsail object storage access keys logged
- Summary: Lightsail object storage allows the creation of access keys which were logged to CloudTrail (both access key and secret key)
- Platform: GCP
- Severity: Medium
- Date: August 5, 2021
- Discoverer: Scott Piper, Summit Route
- Customer action: Roll access keys
- References: 
  - https://summitroute.com/blog/2021/08/05/lightsail_object_storage_concerns-part_1/

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

### Fall 2021, SOC 2 Type 2 failure
- Summary: Information is under NDA, but anyone with an AWS account can read it on page 98.
- Platform: AWS
- Severity: Low
- Date: November 15, 2021
- Discoverer:  Scott Piper 
- Customer action: N/A
- References: 
  - https://twitter.com/AWSSecurityInfo/status/1460326602982793220




