# Cloud Service Provider security mistakes
This page lists security mistakes by cloud service providers (AWS, GCP, and Azure). These are publicly recognizable mistakes on the cloud providers' side of the shared responsibility model. This may be CVEs or bug bounties for issues in the services they run, but could also be in client software they provide, guidance they have given, failed audit tests in their SOC 2 Type 2, security incidents, and more.  

Whether an issue is included or not is hard to define and thus opinionated.  For my definition of a mistake, I am not including business decisions such as AWS releasing a service before it has Cloudtrail auditing support, or technical decisions by the cloud providers such as the ease with which an S3 bucket can be made public. I'm avoiding GSuite and Office365 issues, and security incidents at the companies that did not seem to impact the cloud services for customers (ex. when Amazon's Twitch was hacked, it didn't impact AWS customers). 

The purpose of this project is to ensure there is a record of these mistakes. Although I believe using cloud providers is often a much better decision than self-hosting, it's important to hold them accountable by recognizing their security mistakes.

Where possible I also want to ensure customers know what steps they can take to detect or prevent the issues identified.  Mitre, which is the organization that manages CVEs, has generally avoided providing CVEs for security issues of the cloud providers under the assumption that all issues can be resolved by the cloud provider and therefore do not need a tracking number. This view is sometimes incorrect, and even when the issue can be resolved by the cloud provider, I still believe it warrants having a record.  Similar views are expanded on by Alon Schindel and Shir Tamari from Wiz.io in their post [Security industry call to action: we need a cloud vulnerability database](
 https://www.wiz.io/blog/security-industry-call-to-action-we-need-a-cloud-vulnerability-database).  

I've made an attempt at creating such a record here. This data would be better maintained in a database for sorting and filtering.

## Field explanations

#### Name: Name of the vulnerability if available, or a short explanation
- Summary: Explanation of the issue
- Platform: cloud provider (AWS, GCP, or Azure)
- Severity: Takes into consideration how potentially widespread this issue was (was it a newly released service or one that has been around for years?), what would be achieved by an attacker abusing this issue (full data compromise?), and whether other issues needed to be chained to this for it to be exploited (did the attacker need privileges in your environment already? Did they need special knowledge of your environment?)
- Date: Date this was discovered. The actual date where this impacted customers may have been much earlier, and the date it was published, or fixed may be much later.
- Discoverer: Individuals who found the issue and where they worked at the time
Customer action: Whether this issue was entirely outside of their control to take action on, or if they could fix it.
- References: Publication of the research and response from the cloud provider if it exists.

# Issues

### ChaosDB
- Summary: All CosmosDB customer data compromised. Series of mistakes by Azure shows systemic lack of security best practices.
- Platform: Azure
- Severity: Critical - All customer data for service compromised for service that had been around since 2017
- Date: August 9, 2021
- Discoverer: Nir Ohfeld and Sagi Tzadik, Wiz.io
- Customer action: Regenerate primary read/write key 
- References: 
  - https://chaosdb.wiz.io/
  - https://www.wiz.io/blog/chaosdb-explained-azures-cosmos-db-vulnerability-walkthrough

### Workspace client RCE - CVE-2021-38112
- Summary: If a user with AWS WorkSpaces 3.0.10-3.1.8 installed visits a page in their web browser with attacker controlled content, the attacker can get zero click RCE under common circumstances.
- Platform: AWS
- Severity: High
- Date: September 21, 2021
- Discoverer: David Yesland, Rhino security
- Customer action: Update client to 3.1.9 or higher
- References: 
  - https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/





