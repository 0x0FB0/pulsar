Function Gen-SSHKey
{
Try {
    Write-Host "Generating sandbox RSA ssh keys."
    ssh-keygen -t rsa -b 4096 -f secrets_storage/sandbox_key -C "sandbox@web" -q -N '""'
    copy secrets_storage\sandbox_key.pub sandbox_storage\sandbox_key.pub
}
Catch {
    Write-Error "Could not generate SSH key.`n`nAre you sure Git tools are installed correctly?`n"
    exit
}
}

Function Check-DockerCompose
{
Try {
    docker-compose | Out-Null
}
Catch {
    Write-Error "Could not execute docker-compose!`n`nAre you sure it is installed correctly?`n"
    exit
}
}

Function Gen-Password
{
    $private:ofs=""
    $Characters = '!#$%&\()*+,-./:;<>?@[]^_{}~1234567890ZXCVBNMASDFGHJKLQWERTYUIOPqwertyuiopasdfghjklzxcvbnm'
    return [String]$Characters[(1..18 | ForEach-Object { Get-Random -Maximum 89 })]
}

Function Gen-Credentials
{
    $django_user    = 'admin'
    $django_pass    = Gen-Password
    $rabbit_user    = 'queue_admin'
    $rabbit_pass    = Gen-Password
    $mysql_user     = 'pulsar_db_user'
    $mysql_pass     = Gen-Password

    Write-Host "`nGenerated default service credentials."
    Write-Host "Store them somewhere safe.`n"
    Write-Host "`nDjango Admin user:`t`t" $django_user
    Write-Host "Django Admin password:`t`t" $django_pass
    Write-Host "`nRabbitMQ queue user:`t`t" $rabbit_user
    Write-Host "RabbitMQ queue password:`t" $rabbit_pass
    Write-Host "`nMySQL database user:`t`t" $mysql_user
    Write-Host "MySQL database password:`t" $mysql_pass
    Write-Host "`n"

    $mysql_config = "MYSQL_RANDOM_ROOT_PASSWORD=yes`nMYSQL_DATABASE=pulsar`nMYSQL_USER="+$mysql_user+"`n"
    $mysql_config = $mysql_config+"MYSQL_PASSWORD="+$mysql_pass
    $rabbit_config = "RABBITMQ_DEFAULT_VHOS=/`nRABBITMQ_DEFAULT_USER="+$rabbit_user+"`n"
    $rabbit_config = $rabbit_config+"RABBITMQ_DEFAULT_PASS="+$rabbit_pass
    $django_config = "DJANGO_ADMIN_USER="+$django_user+"`n"
    $django_config = $django_config+"DJANGO_ADMIN_PASS="+$django_pass

    $mysql_config | Out-File db.env
    $rabbit_config | Out-File queue.env
    $django_config | Out-File web.env

    Write-Host "Credentials written to web.env, db.env and queue.env files."

}

Function Build-Containers {
    Write-Host "Configuration complete."
    $Continue = Read-Host -Prompt 'Do you want to build containers? (y/n)'
    if( $Continue -eq "y" -OR $Continue -eq "Y" )
    {
        Try {
            Write-Host "Downloading images and dependencies."
            Write-Host "This will take while..."
            docker-compose build | Out-Null
            Write-Host "Build finished!"
        }
        Catch {
            Write-Error "Failed to build docker containers."
            exit
        }
    }
    else
    {
    Write-Host "Bye. "
    exit
    }
}

Function Start-Pulsar
{
    Try {
        $Continue = Read-Host -Prompt 'Do you want to start Pulsar now? (y/n)'
         if( $Continue -eq "y" -OR $Continue -eq "Y" )
         {
            Write-Host "Starting Pulsar containers."
            Write-Host "Web service will be available on port 8443."
            docker-compose up
         }
         else
         {
         Write-Host 'Run "docker-compose up" to start it manually.'
         exit
         }
    }
    Catch {
        Write-Error "Failed to start docker containers."
        exit
    }
}

Write-Host "`nPulsar Installation Script`n`n"
Write-Host "Before proceeding make sure you have Docker, Docker Compose and Git tools"
Write-Host "installed on your system.`n"
$Continue = Read-Host -Prompt 'Do you want to countinue? (y/n)'
if( $Continue -eq "y" -OR $Continue -eq "Y" )
{
    Check-DockerCompose
    Gen-SSHKey
    Gen-Credentials
    Build-Containers
    Start-Pulsar
}
else
{
    Write-Host "Bye. "
    exit
}
