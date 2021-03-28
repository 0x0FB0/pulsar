FROM mysql:8.0.18

# Setup the custom configuration
COPY conf/mysqld.cnf /etc/mysql/my.cnf
RUN mkdir /var/log/mysql
RUN chown mysql /var/log/mysql
