FROM debian:10.3-slim

COPY sandbox_key.pub /root/.ssh/authorized_keys
RUN chmod 0600 /root/.ssh/authorized_keys

RUN curl https://sh.rustup.rs -sSf | sh
RUN apt-get update && apt-get install -y netcat less screen openssl nmap net-tools whatweb python3 python3-pip \
    host wget openssh-server git curl
COPY sshd_config /etc/ssh/sshd_config
RUN systemctl enable ssh

RUN mkdir /opt/scan_data/
RUN mkdir /opt/scan_config/

COPY requirements.txt /opt/scan_config/requirements.txt
COPY amass-config.ini /opt/scan_config/amass-config.ini
COPY blacklist.txt /opt/scan_config/blacklist.txt

RUN pip3 install --upgrade pip
RUN pip3 install -r /opt/scan_config/requirements.txt

WORKDIR /opt/
RUN wget "https://dl.google.com/go/go1.16.linux-amd64.tar.gz" -O "/opt/golang.tar.gz"
RUN tar -C /usr/local -xzf /opt/golang.tar.gz
RUN rm "/opt/golang.tar.gz"
ENV PATH="${PATH}:/usr/local/go/bin"
ENV GOPATH=/opt/
ENV PATH="${PATH}:${GOPATH}bin"

RUN git clone https://github.com/jtesta/ssh-audit

# RUN go get github.com/zmap/zdns/zdns
RUN git clone https://github.com/zmap/zdns
RUN cd zdns && go build .
RUN ln -s /opt/zdns/zdns /bin/zdns

WORKDIR /opt/
ENV GO111MODULE=on
RUN go get -v github.com/OWASP/Amass/v3/...

RUN wget https://github.com/initstring/cloud_enum/archive/v0.2.tar.gz
RUN tar -xzf /opt/v0.2.tar.gz
RUN rm /opt/v0.2.tar.gz

WORKDIR /opt/scan_data

ENTRYPOINT service ssh start && /bin/bash
