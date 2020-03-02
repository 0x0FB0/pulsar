# Basic Usage Guide

## Asset view

![asset view](/images/pulsar-guide1.png)

### Adding an asset

An **Add** button (1) allows for creation of new asset object.
An asset definition includes:
- **Name** - A short name of an organization i.e. "ACME INC"
- **Domain** - A root domain used to start enumeration (need to be a resolvable FQDN)

### Scanning an asset

A **Scan** button (2) initiates scanning process and opens up a following policy configuration window:

![scan policy](/images/pulsar-policy.PNG)

Policy settings include:
- **Active Scan** - Defines if active scanner plugins should be enabled i.e. Nmap scan
- **Ports** - Defines how many top network ports should be scanned (Nmap --top-ports argument)
- **Recursive discovery** - Defines if recursive plugins should be enabled i.e. Reverse DNS
- **In-Scope discovery** - Defines if scanner should stick to asset root domain scope
- **Repeat scan** - Defines if periodic scan tasks should be enabled
- **Schedule** - Defines a period that scans will be launched
- **Send notifications** - Defines if email notifications should be sent on new results (requires email configuration)

### Exporting an asset

An **Export** button (3) allows for export of data in following formats:
- **JSON** asset data dump
- **MARKDOWN** report
- **PDF** report

### Examining an asset map

A **Map** button (4) allows for visualization of asset domains on a world map (country statistics).

### Deleting an asset

A **Delete** button (5) allows for deletion of asset object and all related data.
Aditionally, **Schedule** option allows for flushing existing periodic scan tasks.

## Other views
Menu available at the top of the page allows for switchig views to **Dashboard** (6), **Asset** (7) and **Network** (8).
Additionally, **User** (9) menu available at the top right corner points to user details screen including documentation links and REST API token.

## Custom scanner plugins

A **Hand made plugins** section available in Django admin console allows for creation of user defined plugins in form of sandbox bash scripts.

> Be cautious when defining any custom plugins. This can not only break your scans but also cause security issues if done improperly. See [TROUBLESHOOTING.md](/TROUBLESHOOTING.md) for information on how to test custom plugins in sandbox.

Example plugin configuration:

![custom plugin](/images/pulsar-plugin.PNG)

## Collaboration groups

A **Collaboration groups** section available in Django admin console allows for creation of collaboration goups enabling users to an access to asset object.

In order to set up collaboration group, there are two steps needed:

1. Creation of a new collaboration group and assigning specific users and roles to it.

![collab1](/images/pulsar-collab.PNG)

2. Assignment of collaboration group to a specific asset.

![collab2](/images/pulsar-collab2.PNG)

## External APIs integration

OWASP Amass used in this project support variety of different external REST APIs.
In order to use any of them, edit `/portal/pulsar/modules/amass-config.ini` file before installation.

> WARNING: API secrets placed in `amass-config.ini` will be stored on a sandbox container, along other (untrusted) installed tools which can pose a risk of secrets being stolen.

