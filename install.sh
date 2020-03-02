#!/usr/bin/bash
function Gen-SSHKey
{
        echo "Generating sandbox RSA ssh keys."
        ssh-keygen -t rsa -b 4096 -f secrets_storage/sandbox_key -C "sandbox@web" -q -N ''
        cp secrets_storage/sandbox_key.pub sandbox_storage/sandbox_key.pub
        if [ $? -ne 0 ]
        then
            echo -e "\nCould not generate SSH key.\nAre you sure ssh-keygen is installed correctly?\n"
            exit
        fi
}

function Check-DockerCompose
{
    docker-compose version  >&2 2>/dev/null
    if [ $? -ne 0 ]
    then
        echo -e "\nCould not execute docker-compose!\nAre you sure it is installed correctly?\n"
        exit
    fi
}

function Gen-Password
{
    charset='!#$%&\()*+,-./:;<>?@[]^_{}~1234567890ZXCVBNMASDFGHJKLQWERTYUIOPqwertyuiopasdfghjklzxcvbnm'
    </dev/urandom tr -dc "$charset" | head -c 18
}

function Gen-Credentials
{
    django_user='admin'
    django_pass=$(Gen-Password)
    rabbit_user='queue_admin'
    rabbit_pass=$(Gen-Password)
    mysql_user='pulsar_db_user'
    mysql_pass=$(Gen-Password)

    echo -e "\nGenerated default service credentials."
    echo -e "Store them somewhere safe.\n"
    echo -e "\nDjango Admin user:\t\t${django_user}"
    echo -e "Django Admin password:\t\t${django_pass}"
    echo -e "\nRabbitMQ queue user:\t\t${rabbit_user}"
    echo -e "RabbitMQ queue password:\t${rabbit_pass}"
    echo -e "\nMySQL database user:\t\t${mysql_user}"
    echo -e "MySQL database password:\t${mysql_pass}"
    echo -e "\n"

    echo -e "MYSQL_RANDOM_ROOT_PASSWORD=yes\nMYSQL_DATABASE=pulsar\nMYSQL_USER=${mysql_user}\nMYSQL_PASSWORD=${mysql_pass}" > db.env
    echo -e "RABBITMQ_DEFAULT_VHOST=/\nRABBITMQ_DEFAULT_USER=${rabbit_user}\nRABBITMQ_DEFAULT_PASS=${rabbit_pass}" > queue.env
    echo -e "DJANGO_ADMIN_USER=${django_user}\nDJANGO_ADMIN_PASS=${django_pass}" > web.env

    echo "Credentials written to web.env, db.env and queue.env files."

}

function Build-Containers {
    echo "Configuration complete."
    read -n 2 -p 'Do you want to build containers? (y/n) ' Continue
    if [ "$Continue" == "y" ]
    then
        echo -e "\nDownloading images and dependencies."
        echo "This will take while..."
        docker-compose build >&2 2>/dev/null
        if [ $? -ne 0 ]
        then
            echo -e "\nFailed to build docker containers."
            exit
        else
            echo -e "\nBuild finished!"
        fi
    else
        echo -e "\nBye. "
        exit
    fi
}

function Start-Pulsar
{
     read -n 2 -p 'Do you want to start Pulsar now? (y/n) ' Continue
     if [ "$Continue" == "y" ]
     then
        echo "Starting Pulsar containers."
        echo "Web service will be available on port 8443."
        docker-compose up 
        if [[ $? -ne 0 ]]
        then
            echo -e "\nFailed to start docker containers."
            exit
        fi
     else
         echo -e '\nRun "docker-compose up" to start it manually.'
         exit
     fi
}

echo -e "\nPulsar Installation Script\n\n"
echo -e "Before proceeding make sure you have Docker, Docker Compose and ssh-keygen tool"
echo -e "installed on your system.\n"
read -n 2 -p 'Do you want to countinue? (y/n) ' Continue
if [ "$Continue" == "y" ]
then
    Check-DockerCompose
    Gen-SSHKey
    Gen-Credentials
    Build-Containers
    Start-Pulsar
else
    echo -e "\nBye. "
    exit
fi
