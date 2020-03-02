# Pulsar
![0.9.8 Beta](https://img.shields.io/badge/pulsar-v0.9.8b-YELLOW) ![Django](https://img.shields.io/badge/django-3.0.3-GREEN) ![Vue](https://img.shields.io/badge/Vue-2.6.11-BLUE)


![Pulsar](/images/pulsar-banner.PNG)

## What is it?

**Pulsar** is an automated network footprint scanner for Red Teams, Pentesters and Bounty Hunters.
Its focus is on discovery of organization public facing assets with minimal knowledge about its infrastructure. Along with network data visualization, it attempts to give a basic vulnerability score to find infrastructure weak points and their relation to other resources. It can be also used as a custom vulnerability scanner for wide and uncharted scopes.
This software was created with availability and openness in mind, so it is 100% free, and does not require any API keys to use its features.

> This is a beta release, be prepared to notice bugs or even crashes. Help me out and submitt an [issue](../../issues/new).

## What it is not?
- Vulnerability Management Platform
- Full OSINT framework scanner
- Speed oriented tool with immediate results
- Stable enterprise product you can rely on (beta release)

## Key features

- [x] Subdomains discovery
- [x] Cloud resources discovery
- [x] Basic vulnerability scanning
- [x] Scan policies & optimization
- [x] Data visualization
- [x] Collaboration & data export
- [x] Scheduling & notifications
- [x] REST API
- [x] External APIs integration
- [x] OAUTH integration
- [x] Custom scanner extensions


## Integrated projects

- [OWASP Amass](https://owasp.org/www-project-amass/)
- [Nmap](https://nmap.org/)
- [RIPEstat API](https://stat.ripe.net/docs/data_api)
- [CloudEnum](https://github.com/initstring/cloud_enum)
- [SSH Audit](https://github.com/arthepsy/ssh-audit)
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
- [NVD Data Feed](https://nvd.nist.gov/vuln/data-feeds)


## Future ideas

- [ ] Stability and speed improvements.
- [ ] CLI client
- [ ] More open source integrations.
- [ ] More detailed scan settings.
- [ ] IPv4 subnet discovery.
- [ ] Additional confidence tests.
- [ ] Additional frontend user controls.
- [ ] Harvesting false positive metadata for machine learning model.


## Installation instructions

> If you would like to use External APIs see [USAGE.md](/USAGE.md#external-apis-integration)

### Windows

#### Prerequisites

1. **Git-tools**
- Installer is available [here](https://gitforwindows.org/).

2. **Docker** engine and **docker-compose**
- **Docker** installation instructions are available [here](https://docs.docker.com/ee/docker-ee/windows/docker-ee/).
- **docker-compose** installation instructions are available [here](https://docs.docker.com/compose/install/).

> *Prerequisites will be verified during installation process.*

#### Installation

1. Clone or download latest pulsar repository

```
git clone https://github.com/pulsar/
```

3. Run powershell installer

```
PS> .\install.ps1
```
4. Proceed with installer instructions
5. Login to pulsar console at `https://localhost:8443/` with generated default credentials

### Linux

#### Prerequisites

1. **Git-tools**
Install git from package manager of your distribution, i.e.
```
sudo apt install git
```

2. **Docker** engine and **docker-compose**
- **Docker** installation instructions are available [here](https://docs.docker.com/install/linux/docker-ce/debian/).
- **Docker-compose** installation instructions are available [here](https://docs.docker.com/compose/install/).

> Prerequisites will be verified during installation process.

#### Installation

1. Clone or download latest pulsar repository

```
git clone https://github.com/pulsar/
```

3. Run bash installer

```
# ./install.sh
```
4. Proceed with installer instructions
5. Login to pulsar console at `https://localhost:8443/` with generated default credentials


## Architecture
Pulsar is a PaaS based on docker-compose file with pre-installed requirements.
Provided architecture can be easliy scaled, converted and deployed to multiple common cloud environments.
Web application server is based on services such as Nginx, Gunicorn and Django Rest Framework.


### Docker container structure
![Docker chart](/images/diagram.jpg)

> *For more information see* `docker-compose.yml`

## Contribution

### In case of issues
- Feel free to issue a bug report.
- See troubleshooting section [here](/TROUBLESHOOTING.md).

### In case of ideas
- Feel free to issue a change request.
- Feel free to issue a pull request.
- Send me a private message.

### In case you would like to see it hosted
- I'm considering launching a funding campaign.

### In case you like the idea
- Star me and tell your friends!

### In case of general criticism about code quality and architecture
- You don't need to use it.
- Feel free to issue a pull request.

## Documentation

### User guide
Basic usage guide can be found [here](/USAGE.md).

### REST API

Self describing API is available at `/pulsar/api/v1/` endpoint.

### Development

Currently the only available documentation is available at `/admin/doc/` endpoint.
> *Full development documentation will be available in future release.*

## Legal
> :warning: Althrough Pulsar is focusing on basic service fingerprinting, port scanning and banner grabbing might be illegal in some countries. Please make sure you are authorized to perform network scans on targeted resource before using this tool.

| *THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.* |
| --- |
