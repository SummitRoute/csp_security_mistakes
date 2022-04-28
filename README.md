# Cloud Service Provider security mistakes
This page lists security mistakes by cloud service providers (AWS, GCP, and Azure). These are public mistakes on the cloud providers' side of the shared responsibility model. This may be CVEs or bug bounties for issues in the services they run, but could also be in client software they provide, guidance they have given, failed audit tests in their SOC 2 Type 2, security incidents they have had, and more.  

Whether an issue is included or not is hard to define and thus opinionated.  For my definition of a mistake, I am generally not including business decisions such as AWS releasing a service before it has Cloudtrail auditing support, or some technical decisions by the cloud providers such as the ease with which an S3 bucket can be made public.  Some technical decisions are concerning enough to be listed here though. I'm avoiding GSuite and Office365 issues, or issues that are not specifically cloud issues (ex. Active Directory issues unless it specifically impacts Azure AD). I am not including security incidents at the companies that did not seem to impact the cloud services for customers (ex. when Amazon's Twitch was hacked, it didn't impact AWS customers), or security incidents of their customers (ex. Capital One's breach on AWS). I'm not including WAF bypasses as WAFs are inherently bypassable.

The purpose of this project is to ensure there is a record of these mistakes. Although I believe using cloud providers is often a much better decision than self-hosting, it's important to hold them accountable by recognizing their security mistakes.

Where possible I also want to ensure customers know what steps they can take to detect or prevent the issues identified.  Mitre, which is the organization that manages CVEs, has generally avoided providing CVEs for security issues of the cloud providers under the assumption that all issues can be resolved by the cloud provider and therefore do not need a tracking number. This view is sometimes incorrect, and even when the issue can be resolved by the cloud provider, I still believe it warrants having a record.

Concern has been raised that AWS restricts what they allow to be pentested (their [guidance](https://aws.amazon.com/security/penetration-testing/) and [historic guidance](http://web.archive.org/web/20151212173314/https://aws.amazon.com/security/penetration-testing/)) and has no [bug bounty](https://twitter.com/SpenGietz/status/1252971138352701442) which are believed by some to limit the issues that become public with AWS.

## Similar work
- Alon Schindel and Shir Tamari from Wiz.io have been advocating for the desire for a cloud vulnerability database through their [blog post](https://www.wiz.io/blog/security-industry-call-to-action-we-need-a-cloud-vulnerability-database/), Slack forum (linked from their blog post), and [Black Hat talk](https://www.youtube.com/watch?v=JEA_Zgi8Tjg&list=PLH15HpR5qRsW62N-GLRb1q56Zr7sm10rF&index=9).
- Christophe Parisel has described a concept called [Piercing Index](https://www.linkedin.com/posts/parisel_cloud-providers-flaw-assessment-ugcPost-6896378757695856640-NBoY/) for classifying the impact of cloud provider vulnerabilities.

## Field explanations

#### Name: Name of the vulnerability if available, or a short explanation
- Summary: Explanation of the issue
- Platform: cloud provider (AWS, GCP, or Azure)
- Severity: My opinion of how bad this is, in relation to other issues on this page.
- Date: Date this was discovered or published if unknown. The actual date where this impacted customers may have been much earlier, and the date it was published, or fixed may be much later. This is just to give this list some sort of ordering.
- Discoverer: Individuals who found the issue and where they worked at the time
- Customer action: Whether there is anything a customer could do as follow-up to this issue.
- References: Publication of the research and response from the cloud provider if it exists.

---------------------------------------------------------------------------------------
# Issues


### GCP Default compute account is project Editor
- Summary: When the compute API is enabled on a GCP Project, the default compute account is created. This account gets the primitive role Editor assigned by default, which allows for a wide variety of privilege excalation and resource abuse in the project. Especially, all new VMs created inherit this permissions by default. This issue is arguably a technical decision by GCP, but the documents advise customers to undo this.
- Platform: GCP
- Severity: Medium
- Date: Since the creation of GCP
- Customer action: Remove these permissions, it can be done via an organization policy
- References:
  - https://cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts#disable_service_account_default_grants

### AWS: Signature version 1 (SigV1) is insecure
- Summary: When making authenticated API requests to AWS, the requests must be signed with your
AWS access key. The initial signing algorithm, SigV1, was vulnerable to collisions. A person-in-the-middle attack would be able to modify signed requests via specially constructed collisions.
- Platform: AWS
- Severity: Medium
- Date: until December 18th, 2008
- Discoverer: Colin Percival
- Customer action: N/A, SigV1 is deprecated at this point
- References:
  - http://www.daemonology.net/blog/2008-12-18-AWS-signature-version-1-is-insecure.html

### AWS: AWS published official AMIs with recoverable deleted files
- Summary: Researchers, while investigating the security posture of Public AMIs, were able to undelete files from an official image that was published by Amazon AWS.
- Platform: AWS
- Severity: Low
- Date: June, 2011
- Discoverer: Marco Balduzzi, Jonas Zaddach, Davide Balzarotti, Engin Kirda, Sergio Loureiro
- Customer action: Follow [best practices](https://aws.amazon.com/articles/how-to-share-and-use-public-amis-in-a-secure-manner/) when sharing Public AMIs
- References:
  - http://seclab.nu/static/publications/sac2012ec2.pdf

### AWS: AssumeRole vendor issues with confused deputy
- Summary: Vendors may allow customers to access the data of other customers. Although this is a misconfiguration with the vendors, AWS could have better helped prevent and detect this issue.
- Platform: AWS
- Severity: Medium
- Date: November 16, 2016
- Discoverer: Daniel Grzelak, Atlassian
- Customer action: Audit your vendor roles
- References:
  - https://www.youtube.com/watch?v=8ZXRw4Ry3mQ
  - https://www.praetorian.com/blog/aws-iam-assume-role-vulnerabilities/

### AWS: Bypasses in IAM policies and over-privileged
- Summary: Repeated examples of AWS provided managed policies or guidance in documentation for policies with mistakes that allow the policies to by bypassed. Generically, there are also over-privileged policies and policies with spelling mistakes and other issues.
- Platform: AWS
- Severity: Medium
- Date: November 17, 2017 (date is of the first issue, references provide other examples by various individuals)
- Discoverer: Multiple findings
- Customer action: Review the policies provided by AWS
- References:
  - https://duo.com/blog/potential-gaps-in-suggested-amazon-web-services-security-policies-for-mfa
  - https://summitroute.com/blog/2019/06/18/aws_iam_managed_policy_review/
  - https://medium.com/ymedialabs-innovation/an-aws-managed-policy-that-allowed-granting-root-admin-access-to-any-role-51b409ea7ff0
  - https://www.tenchisecurity.com/blog/thefaultinourstars

### AWS: Launching EC2s did not require specifying AMI owner: CVE-2018-15869
- Summary: Attackers had put malicious AMIs in the marketplace to abuse the CLI's way of selecting what AMI to use. Although the concept of planting  malicious AMIs had existed for a while (ex. in the 2009 presentation "Clobbering the clouds" by Nicholas Arvanitis, Marco Slaviero, and Haroon Meer) it had not been used specifically to target this issue with the CLI.
- Platform: AWS
- Severity: Medium
- Date: August 13, 2018
- Discoverer: Megan Marsh (https://github.com/SwampDragons)
- Customer action: Update CLI and other tools that create EC2s
- References:
  - https://github.com/hashicorp/packer/issues/6584

### AWS: Resource policy confused deputy issue with services
- Summary: Resource policies lacked a way of restricting service access to only your own account, allowing an attacker to leverage a service to potentially access your resources. Originally discovered by Dan Peebles and presented at re:Invent in 2018, this issue did not gain enough attention to be fixed until Shir Tamari and Ami Luttwak from Wiz presented it at Black Hat 2021.
- Platform: AWS
- Severity: Low
- Date: November 28, 2018
- Discoverer: Dan Peebles, Bridgewater
- Customer action: Update vulnerable IAM policies (add scoping condition)
- References:
  - https://www.youtube.com/watch?v=F3JmBhTQmyY&t=2475s
  - https://www.wiz.io/blog/black-hat-2021-aws-cross-account-vulnerabilities-how-isolated-is-your-cloud-environment

### Azure: Cloudshell terminal escape
- Summary: If attacker controlled data is viewed in Cloudshell it could have led to code execution.
- Platform: Azure
- Severity: Medium
- Date: January 9, 2019
- Discoverer: Felix Wilhelm, Google
- Customer action: N/A
- References:
  - https://twitter.com/_fel1x/status/1083085715565621250

### AWS: VPC Hosted Zones unauditable
- Summary: For 6 years, it was not possible to see what hosted zones an attacker may have created in an account. This issue could be viewed as a business decision that adding the ability to viewing this data was not worthwhile, but the delay is significant and would allow someone that had compromised an environment to maintain a backdoor. 
- Platform: AWS
- Severity: Low
- Date: May 13, 2019
- Discoverer: Ryan Gerstenkorn (https://twitter.com/Ryan_Jarv/)
- Customer action: Audit your VPC hosted zones
- References:
  - https://twitter.com/__steele/status/1273748905826455552
  - https://blog.ryanjarv.sh/2019/05/24/backdooring-route53-with-cross-account-dns.html


### AWS: ALB HTTP request smuggling
- Summary: ALBs found vulnerable to HTTP request smuggling (desync attack).
- Platform: AWS
- Severity: Medium
- Date: October 4, 2019
- Discoverer: Arkadiy Tetelman (https://twitter.com/arkadiyt), Chime; original issue by James Kettle (https://twitter.com/albinowax), Portswigger
- Customer action: Configure setting on your ALBs
- References:
  - https://twitter.com/arkadiyt/status/1180174359840862209
  - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#load-balancer-attributes

### AWS: AWS employee posts confidential AWS data, including possibly customer access keys and other customer information
- Summary: AWS employee pushed data to a public github bucket.  AWS's public statement is that "the code repository was used by the engineer in a personal capacity, and claimed no customer data or company systems were exposed." but it appears that minimally there was AWS confidential data, and also may have included various forms of confidential customer information (correspondance, access keys, and more). See the referenced stories and debate [here](https://github.com/SummitRoute/csp_security_mistakes/issues/17).
- Platform: AWS
- Severity: Critical
- Date: January 13, 2020
- Discoverer: Upguard
- Customer action: Roll impacted credentials
- References:
  - https://www.upguard.com/breaches/identity-and-access-misstep-how-an-amazon-engineer-exposed-credentials-and-more
  - https://www.theregister.com/2020/01/23/aws_engineer_credentials_github/

### GCP: AI Hub Jupyter Notebook instance CSRF
- Summary: AI Hub Jupyter Notebook server lacked a check of the Origin header that led to a CSRF vulnerability. An attacker could have read sensitive data and execute arbitrary actions in customer environments.
- Platform: GCP
- Severity: Medium
- Date: March 10, 2020
- Discoverer: s1r1us
- Customer action: N/A
- References:
  - https://blog.s1r1us.ninja/research/cookie-tossing-to-rce-on-google-cloud-jupyter-notebooks

### AWS: GuardDuty detection bypass via cloudtrail:PutEventSelectors
- Summary: GuardDuty detects CloudTrail being disabled, but did not detect if you filtered out all events from CloudTrail, resulting in defenders having no logs to review. Require privileged access in victim account, resulting in limited visibility.
- Platform: AWS
- Severity: Low
- Date: April 23, 2020
- Discoverer: Spencer Gietzen, Rhino Security
- Customer action: Setup detections independent of GuardDuty
- References:
  - https://github.com/RhinoSecurityLabs/Cloud-Security-Research/tree/master/AWS/cloudtrail_guardduty_bypass

### GCP and AWS: GKE `CAP_NET_RAW` metadata service MITM root privilege escalation
- Summary: An attacker gaining access to a hostNetwork=true container with CAP_NET_RAW capability can listen to all the traffic going through the host and inject arbitrary traffic, allowing to tamper with most unencrypted traffic (HTTP, DNS, DHCP, ...), and disrupt encrypted traffic. In GKE the host queries the metadata service at `http://169.254.169.254` to get information, including the authorized ssh keys. By manipulating the metadata service responses, injecting our own ssh key, it is possible to gain root privilege on the host.
- Platform: Azure
- Severity: Medium
- Date: June 15, 2020
- Discoverer: Etienne Champetier
- Customer action: N/A
- References:
  - https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE/

### AWS: XSS on EC2 web console
- Summary: Display of EC2 tags had XSS
- Platform: AWS
- Severity: Low
- Date: July 1, 2020
- Discoverer: Johann Rehberger
- Customer action: N/A
- References:
  - https://embracethered.com/blog/posts/2020/aws-xss-cross-site-scripting-vulnerability/

### AWS: S3 Crypto SDK vulns: CVE-2020-8912 and CVE-2020-8911
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

### AWS: Terms and conditions allows sharing customer data
- Summary: Use of the AI services on AWS allows customer data to be moved outside of the regions it is used in and potentially shared with third-parties.
- Platform: AWS
- Severity: Medium
- Date: July 8, 2020
- Discoverer: Ben Bridts
- Customer action: Opt out via Organization AI opt-out policy: https://summitroute.com/blog/2021/01/06/opting_out_of_aws_ai_data_usage/
- References:
  - https://twitter.com/benbridts/status/1280934515305824256

### AWS: Execution in CloudFormation service account
- Summary: Ability to run arbitrary Lambda code in an AWS managed account, with privileges to access some data of other customer accounts
- Platform: AWS
- Severity: Critical
- Date: August 26, 2020
- Discoverer: Aidan Steele (https://twitter.com/__steele) and Ian Mckay (https://twitter.com/iann0036)
- Customer action: N/A
- References:
  - https://onecloudplease.com/blog/security-september-cataclysms-in-the-cloud-formations

### AWS: CloudFormation denial of service (in a single account)
- Summary: An attacker with the ability to create CloudFormation stacks could cause a denial-of-service on some CloudFormation actions within a single AWS account.
- Platform: AWS
- Severity: Low
- Date: September 1, 2020
- Discoverer:  Ian McKay (https://twitter.com/iann0036)
- Customer action: N/A
- References:
  - https://onecloudplease.com/blog/security-september-fun-with-fncidr

### AWS: Identification of privileges without being logged by CloudTrail
- Summary: An attacker could figure out what privileges they have in a victim account, without being logged in CloudTrail. It took AWS over 273 days to fix this.
- Platform: AWS
- Severity: Low
- Date: September 2, 2020
- Discoverer:  Nick Frichette (https://twitter.com/Frichette_n)
- Customer action: N/A
- References:
  - https://frichetten.com/blog/aws-api-enum-vuln/
  - https://github.com/Frichetten/aws_stealth_perm_enum

### AWS: Timing attack with Lambda and CloudWatch Synthetics
- Summary: Ability to violate the immutability of Lambda versions via a timing attack against CloudWatch Synthetics.
- Platform: AWS
- Severity: Low
- Date: September 15, 2020
- Discoverer:  Ian McKay (https://twitter.com/iann0036)
- Customer action: N/A
- References:
  - https://onecloudplease.com/blog/security-september-racing-against-cloudwatch-synthetics-canaries

### AWS: CloudFormer review
- Summary: Audit of AWS open-source project identifies so many issues AWS takes it down
- Platform: AWS
- Severity: Low
- Date: September 25, 2020
- Discoverer: Karim El-Melhaoui (https://twitter.com/KarimMelhaoui)
- Customer action: N/A
- References:
  - https://blog.karims.cloud/2020/09/25/cloudformer-review-part-1.html

### GCP: DHCP abuse for code exec
- Summary: Under certain conditions (which I don't entirely understand), an attacker can flood DHCP packets to the victim VM, allowing it to impersonate the Metadata server, and grant themself SSH access.
- Platform: GCP
- Severity: Medium
- Date: September 26, 2020
- Discoverer:  Imre Rad
- Customer action: N/A
- References:
  - https://github.com/irsl/gcp-dhcp-takeover-code-exec

### AWS: Encryption SDK issues
- Summary:
- Platform: AWS
- Severity: Low
- Date: September 28, 2020
- Discoverer: Thái "thaidn" Dương (https://twitter.com/XorNinja), Google
- Customer action: Update SDK
- References:
  - https://twitter.com/XorNinja/status/1310587707605659649
  - https://vnhacker.blogspot.com/2020/09/advisory-security-issues-in-aws-kms-and.html

### AWS: S3 bucket tagging not restricted
- Summary: Lack of the privilege s3:PutBucketTagging did not restrict the ability to tag S3 buckets
- Platform: AWS
- Severity: Low
- Date: September 28, 2020
- Discoverer:  Ian Mckay (https://twitter.com/iann0036)
- Customer action: N/A
- References:
  - https://onecloudplease.com/blog/security-september-still-early-days-for-abac

### GCP: Exfiltrate data via the logs of GCP Org policy
- Summary: Upon blocking a request, GCP Org policy constraints were logging the deny logs in Principal's project and the blocking project. An attacker could use those logs to exfiltrate any data, by making request from a Principal they own from a defender project.
- Platform: GCP
- Severity: Low
- Date: October 12, 2020
- Discoverer: Jonathan Rault, TrustOnCloud
- Customer action: Review denied logs in the defender project, because it was also logged there.
- References: 
  - https://trustoncloud.com/exfiltrate-data-from-your-super-secure-google-cloud-project-using-the-security-control-built-to-prevent-it/

### AWS: Lack of internal change controls for IAM managed policies
- Summary: Repeated examples of AWS releasing or changing IAM policies they obviously shouldn't have (CheesepuffsServiceRolePolicy, AWSServiceRoleForThorInternalDevPolicy, AWSCodeArtifactReadOnlyAccess.json, AmazonCirrusGammaRoleForInstaller). The worst being the ReadOnlyAccess policy having almost all privileges removed and unexpected ones added.
- Platform: AWS
- Severity: Low
- Date: October 15, 2020
- Customer action: N/A
- References:
  - https://twitter.com/__steele/status/1316909785607012352

### AWS: Route table modification to imitate metadata service
- Summary: An attacker with sufficient privileges in AWS to modify the route table and some other EC2 privileges, could pretend to be a metadata server and provide an attacker controlled bootup script to EC2s to move laterally.
- Platform: AWS
- Severity: Low
- Date: October 19, 2020
- Discoverer:  Ryan Gerstenkorn (https://twitter.com/Ryan_Jarv/)
- Customer action: N/A
- References:
  - https://github.com/RyanJarv/EC2FakeImds
  - https://blog.ryanjarv.sh/2020/10/19/imds-persistence.html  

### AWS: Fall 2020, SOC 2 Type 2 failure
- Summary: Information is under NDA, but anyone with an AWS account can read it on page 120 and 121.
- Platform: AWS
- Severity: Low
- Date: December 22, 2020
- Customer action: N/A
- References:
  - https://twitter.com/awswhatsnew/status/1341461386983952384

### AWS: Cloudshell terminal escape
- Summary: If attacker controlled data is viewed in Cloudshell it could have led to code execution. This exact same issue existed in Azure previously.
- Platform: AWS
- Severity: Medium
- Date: February 8, 2021
- Discoverer: Felix Wilhelm, Google
- Customer action: N/A
- References:
  - https://bugs.chromium.org/p/project-zero/issues/detail?id=2154
  - https://twitter.com/_fel1x/status/1391712232380194818

### GCP: Org policies bypass
- Summary: Allows an attacker with privileges in the account to share resources outside of the account even when an org policy restricts this, thus enabling them to backdoor their access.
- Platform: GCP
- Severity: Medium
- Date: May 15, 2021
- Discoverer: Kat Traxler (https://twitter.com/NightmareJS)
- Customer action: N/A
- References:
  - https://kattraxler.github.io/gcp/hacking/2021/09/10/gcp-org-policy-bypass-ai-notebooks.html

### AWS: XSS in web console
- Summary: If an attacker can launch elasticbeanstalk in the victim environment and get a victim to view a page in the web console, they can get XSS.
- Platform: AWS
- Severity: Low
- Date: June 3, 2021
- Discoverer: Nick Frichette (https://twitter.com/Frichette_n)
- Customer action: N/A
- References:
  - https://twitter.com/Frichette_n/status/1400517723910819844
  - https://frichetten.com/blog/xss_in_aws_console/

### AWS: Lightsail object storage access keys logged
- Summary: Lightsail object storage allows the creation of access keys which were logged to CloudTrail (both access key and secret key)
- Platform: AWS
- Severity: Medium
- Date: August 5, 2021
- Discoverer: Scott Piper, Summit Route
- Customer action: Roll access keys
- References:
  - https://summitroute.com/blog/2021/08/05/lightsail_object_storage_concerns-part_1/

### Azure: ChaosDB
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

### Azure: Azurescape
- Summary: Cross-account container escape
- Platform: Azure
- Severity: Critical
- Date: September 9, 2021
- Discoverer: Yuval Avrahami, Palo Alto
- Customer action: "revoking any privileged credentials that were deployed to the platform before Aug. 31, 2021, and checking their access logs for irregularities."
- References:
  - https://unit42.paloaltonetworks.com/azure-container-instances/

### AWS: BreakingFormation
- Summary: Read access of host of AWS internal Cloudformation service via XXE SSRF. The level of access with the compromised IAM role from there is unclear.
- Platform: AWS
- Severity: Critical
- Date: September 9, 2021
- Discoverer: Tzah Pahima, Orca
- Customer action: N/A
- References:
  - https://orca.security/resources/blog/aws-cloudformation-vulnerability/
  - https://aws.amazon.com/security/security-bulletins/AWS-2022-001/

### Azure: Log analytics role privesc
- Summary: Privilege escalation of Log Analytics Contributor role to Subscription Contributor role.
- Platform: Azure
- Severity: Medium
- Date: September 13, 2021
- Discoverer: Karl Fosaaen, SPI
- Customer action: N/A
- References:
  - https://www.netspi.com/blog/technical/cloud-penetration-testing/escalating-azure-privileges-with-the-log-analystics-contributor-role/

### Azure: OMIGOD
- Summary: Azure forces the install of an agent on Linux VMs, which contained a vuln that would grant root RCE if an attacker could send a web request to them
- Platform: Azure
- Severity: Critical
- Date: September 14, 2021
- Discoverer: Nir Ohfeld, Wiz.io
- Customer action: N/A, client needed to be auto-updated
- References:
  - https://www.wiz.io/blog/secret-agent-exposes-azure-customers-to-unauthorized-code-execution

### GCP IAP bypass
- Summary: Convincing a victim to click a specially crafted link would allow the attacker to bypass the Identity-Aware Proxy (a core component of BeyondCorp).
- Platform: GCP
- Severity: Medium
- Date: September 17, 2021
- Discoverer: Unknown
- Customer action: N/A
- References:
  - https://cloud.google.com/support/bulletins#gcp-2021-020

### AWS Workspace client RCE - CVE-2021-38112
- Summary: If a user with AWS WorkSpaces 3.0.10-3.1.8 installed visits a page in their web browser with attacker controlled content, the attacker can get zero click RCE under common circumstances.
- Platform: AWS
- Severity: High
- Date: September 21, 2021
- Discoverer: David Yesland, Rhino security
- Customer action: Update client to 3.1.9 or higher
- References:
  - https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/

### AWS: SuperGlue
- Summary: Compromise of internal AWS Glue service to assume the glue role in any AWS account that used glue.
- Platform: AWS
- Severity: Critical
- Date: September 30, 2021
- Discoverer: Yanir Tsarimi, Orca
- Customer action: N/A
- References:
  - https://orca.security/resources/blog/aws-glue-vulnerability/
  - https://aws.amazon.com/security/security-bulletins/AWS-2022-002/

### Azure Active Directory information disclosure vulnerability (CVE-2021-42306)
- Summary: Automation Account “Run as” credentials (PFX certificates) were being stored in cleartext, in Azure Active Directory (AAD). These credentials were available to anyone with the ability to read information about App Registrations (typically most AAD users).
- Platform: Azure
- Severity: High
- Date: October 7, 2021
- Discoverer:  Karl Fosaaen, netspi
- Customer action: Regenerate exposed certificate
- References:
  - https://msrc-blog.microsoft.com/2021/11/17/guidance-for-azure-active-directory-ad-keycredential-property-information-disclosure-in-application-and-service-principal-apis/
  - https://github.com/microsoft/aad-app-credential-tools/blob/main/azure-migrate/azure-migrate-credential-rotation-guide.md
  - https://www.netspi.com/blog/technical/cloud-penetration-testing/azure-cloud-vulnerability-credmanifest/


### AWS API Gateway HTTP header smuggling
- Summary: A flaw in AWS API Gateway enabled hiding HTTP request headers. Tampering with HTTP requests visibility enabled bypassing IP restrictions, cache poisoning and request smuggling.
- Platform: AWS
- Severity: Low
- Date: November 10, 2021
- Discoverer:  Daniel Thatcher, intruder.io
- Customer action: N/A
- References:
  - https://www.intruder.io/research/practical-http-header-smuggling

### AWS Fall 2021, SOC 2 Type 2 failure
- Summary: Information is under NDA, but anyone with an AWS account can read it on page 98.
- Platform: AWS
- Severity: Low
- Date: November 15, 2021
- Customer action: N/A
- References:
  - https://twitter.com/AWSSecurityInfo/status/1460326602982793220

### AWS SageMaker Jupyter Notebook instance CSRF
- Summary: AWS SageMaker Notebook server lacked a check of the Origin header that led to a CSRF vulnerability. An attacker could have read sensitive data and execute arbitrary actions in customer environments. This issue is identical to [GCP's issue](https://github.com/SummitRoute/csp_security_mistakes#gcp-ai-hub-jupyter-notebook-instance-csrf) from a year earlier.
- Platform: AWS
- Severity: Medium
- Date: December 2, 2021
- Discoverer:  Gafnit Amiga, Lightspin
- Customer action: N/A
- References:
  - https://blog.lightspin.io/aws-sagemaker-notebook-takeover-vulnerability

### Azure: AutoWarp
- Summary: An exposed endpoint in the Azure Automation Service allowed to steal Azure API credentials from other customers
- Platform: Azure
- Severity: Critical
- Date: December 6, 2021
- Discoverer: Yanir Tsarimi, Orca
- Customer action: N/A. As a general practice, use the least-privilege principle, including on managed identities assigned to automation accounts. While this would not have prevented the leakage of API credentials, it would have reduced the blast radius.
- References:
  - https://orca.security/resources/blog/autowarp-microsoft-azure-automation-service-vulnerability/

### AWS RDS local file read
- Summary: Able to read local files on the host of the RDS, found AWS creds. 
- Platform: AWS
- Severity: High
- Date: December 9, 2021
- Discoverer:  Gafnit Amiga, Lightspin
- Customer action: N/A
- References:
  - https://blog.lightspin.io/aws-rds-critical-security-vulnerability
  - https://aws.amazon.com/security/security-bulletins/AWS-2022-004/

### AWS: Log4Shell Hot Patch Vulnerable to Container Escape and Privilege Escalation
- Summary: AWS's hotpatch for Log4shell patched the RCE but enabled a container escape.
- Platform: AWS
- Severity: High
- Date: December 14, 2021
- Discoverer: Yuval Avrahami, Palo Alto
- References:
  - https://unit42.paloaltonetworks.com/aws-log4shell-hot-patch-vulnerabilities/
  - https://aws.amazon.com/security/security-bulletins/AWS-2022-006/


### Azure NotLegit: App Service vulnerability exposed source code repositories
- Summary:
- Platform: Azure
- Severity: High
- Date: December 21, 2021
- Discoverer: Shir Tamari, Wiz.io
- Customer action: Remove these permissions, it can be done via an organization policy
- References:
  - https://www.wiz.io/blog/azure-app-service-source-code-leak/

### AWS: Overprivileged AWS Support IAM Role Policy
- Summary: AWS added `s3:getObject` action to `AWSSupportServiceRolePolicy` IAM Policy used by AWS Support teams.
- Platform: AWS
- Severity: Medium
- Date: December 22, 2021
- Discoverer: [Scott Piper](https://twitter.com/0xdabbad00/status/1473448889948598275)
- Customer action: Use KMS-CMK for bucket encryption, Use Least privilege on resources policies (Buckets)
- References:
  - https://aws.amazon.com/security/security-bulletins/AWS-2021-007/

### Azure ExtraReplica: Cross-account database vulnerability in Azure PostgreSQL
- Summary: Read access to other customer's Azure Database for PostgreSQL Flexible Server
- Platform: Azure
- Severity: Critical
- Date: January 11, 2022
- Discoverer:  Sagi Tzadik, Nir Ohfeld, Shir Tamari, and Ronen Shustin from Wiz.o
- Customer action: N/A
- References:
  - https://www.wiz.io/blog/wiz-research-discovers-extrareplica-cross-account-database-vulnerability-in-azure-postgresql/
  - https://msrc-blog.microsoft.com/2022/04/28/azure-database-for-postgresql-flexible-server-privilege-escalation-and-remote-code-execution


### AWS: CVE-2022-25165: Privilege Escalation to SYSTEM in AWS VPN Client
- Summary: Windows privesc in the AWS VPN client
- Platform: AWS
- Severity: Low
- Date: February 15, 2022
- Discoverer: David Yesland, Rhino Security
- References:
  - https://rhinosecuritylabs.com/aws/cve-2022-25165-aws-vpn-client/
  - https://aws.amazon.com/security/security-bulletins/AWS-2022-005/


