# Pulsar [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Check%20out%20Pulsar%20project%20at%20github!&url=https://fooballz.github.io/pulsar)
![1.0.0](https://img.shields.io/badge/version-1.0.0-RED) ![Django](https://img.shields.io/badge/django-3.0.3-GREEN) ![Vue](https://img.shields.io/badge/Vue-2.6.11-BLUE)     [![DeepSource](https://static.deepsource.io/deepsource-badge-light-mini.svg)](https://deepsource.io/gh/FooBallZ/pulsar/?ref=repository-badge)


![Pulsar](/images/pulsar-banner.PNG)

## What is it?

**Pulsar** is an automated network footprint scanner for Red Teams, Pentesters and Bounty Hunters.
Its focused on discovery of organization public facing assets with minimal knowledge about its infrastructure. Along with network data visualization, it attempts to give a basic vulnerability score to find infrastructure weak points and their relation to other resources. It can be also used as a custom vulnerability scanner for wide and uncharted scopes.
This software was created with availability and openness in mind, so it is 100% free, and does not require any API keys to use its features.

## v1 is here!

Release includes major stability improvements and some new features.

Many thanks for all contributions so far!

New features:
- TLD Expansion discovery
- Improved reporting (including new CSV file format)

## What it is not?
- Vulnerability Management Platformn
- Full OSINT framework scanner
- Speed oriented tool with immediate results

## Key features

- [x] Subdomains discovery
- [x] TLD discovery
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
- [ZMap](https://zmap.io/)
- [Nmap](https://nmap.org/)
- [RIPEstat API](https://stat.ripe.net/docs/data_api)
- [CloudEnum](https://github.com/initstring/cloud_enum)
- [SSH Audit](https://github.com/arthepsy/ssh-audit)
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
- [NVD Data Feed](https://nvd.nist.gov/vuln/data-feeds)


## Future ideas

- [ ] CLI client
- [ ] More open source integrations.
- [ ] Stability and speed improvements.
- [ ] More detailed scan settings.
- [ ] IPv4 subnet discovery.
- [ ] Additional confidence tests.
- [ ] Additional frontend user controls.
- [ ] Harvesting false positive metadata for machine learning model.


## Installation instructions

> If you would like to use External APIs see [USAGE.md](https://fooballz.github.io/pulsar/USAGE.html)

> In order to use email notifications, edit `EMAIL_BACKEND SETTINGS` in `portal/portal/settings.py` **before the 
>installation** or web container will need to be rebuild.

### Windows

#### Prerequisites

1. **Git-tools**
- Installer is available [here](https://gitforwindows.org/).

2. **Docker** engine and **docker-compose**
- **Docker** installation instructions are available [here](https://docs.docker.com/ee/docker-ee/windows/docker-ee/).
- **docker-compose** installation instructions are available [here](https://docs.docker.com/compose/install/).

> *Prerequisites will be verified during installation process.*

> :warning: For Windows 10 Home users: 
Since Docker desktop cannot be installed on Windows 10 Home,
please install Hyper-V manually, instructions can be found [here](https://gist.github.com/talon/4191def376c9fecae78815454bfe661c) 

#### Installation

1. Clone or download latest pulsar repository

```
git clone https://github.com/FooBallZ/pulsar
```

3. Run powershell installer

```
PS> .\install.ps1
```
4. Proceed with installer instructions
> :warning: Make sure you store generated password before further installation steps. Administrator password can be changed in Django admin console at `/admin/`.

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
git clone https://github.com/FooBallZ/pulsar
```

3. Run bash installer

```
# ./install.sh
```
4. Proceed with installer instructions
> :warning: Make sure you store generated password before further installation steps. Administrator password can be changed in Django admin console at `/admin/`.

5. Login to pulsar console at `https://localhost:8443/` with generated default credentials

### Video guide

In case you have hard times installing Pulsar or wondering how to install dependencies:

*Game Flexer* created a linux installation tutorial available [here](https://www.youtube.com/watch?v=AwCwmf7qfEk).

> :warning: I do not take responsibility for any of this content including links in the description.

## Contribution

Have an idea, or a tool you would like to integrate? Feel free to issue a pull request.

Current issues and features can be found at [projects](https://github.com/FooBallZ/pulsar/projects) section.
Feel free to pick something.

Currently most help is needed with Vue.js frontend and Docker optimization.

### In case you like the idea
- Star me and tell your friends!
- Hit the sponsor button!

### In case of issues
- Feel free to issue a bug report.
- See troubleshooting section [here](https://fooballz.github.io/pulsar/TROUBLESHOOTING.html).

### In case of ideas
- Feel free to issue a change request.
- Feel free to issue a pull request.
- Send me a private message.

### In case you would like to see it hosted
- I'm considering launching a funding campaign.

### In case of general criticism about code quality and architecture
- You don't need to use it.
- Feel free to issue a pull request.

## Documentation

### User guide
Basic usage guide can be found [here](https://fooballz.github.io/pulsar/USAGE.html).

### REST API

Self describing API is available at `/pulsar/api/v1/` endpoint.

### Development

Currently the only available documentation is available at `/admin/doc/` endpoint.
> *Full development documentation will be available in future release.*

## Architecture
Pulsar is a PaaS based on docker-compose file with pre-installed requirements.
Provided architecture can be easliy scaled, converted and deployed to multiple common cloud environments.
Web application server is based on services such as Nginx, Gunicorn and Django Rest Framework.


### Docker container structure
![Docker chart](/images/diagram.jpg)

> *For more information see* `docker-compose.yml`

## Legal
> :warning: Althrough Pulsar is focusing on basic service fingerprinting, port scanning and banner grabbing might be illegal in some countries. Please make sure you are authorized to perform network scans on targeted resource before using this tool.

| *THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.* |
| --- |
