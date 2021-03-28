#!/bin/bash

# Copy rabbitmq certificates

cp /home/testca/cacert.pem /home/client/
cp /home/client/* /certs/client_cert/

rabbitmq-server & sleep 1

# Wait for full server operation

until netcat -z 127.0.0.1 5672 ; do
  >&1
  sleep 1
done

# Add rabbitmq user

rabbitmqctl add_user ${RABBITMQ_DEFAULT_USER} ${RABBITMQ_DEFAULT_PASS}
rabbitmqctl set_user_tags ${RABBITMQ_DEFAULT_USER} administrator
rabbitmqctl set_permissions -p / ${RABBITMQ_DEFAULT_USER} ".*" ".*" ".*"

# Wait

tail -f /dev/null & wait
