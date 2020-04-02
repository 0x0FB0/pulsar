# Troubleshooting guide

Due to unexpected and random behavior of scanned services Pulsar is prone to crashes.
In order to better identify the issues there are mulitiple places where usefull information can be gathered.

To restart containers:
```
# docker-compose down
# docker-compose up
```

To rebuild containers after configuration changes:
```
# docker-compose down
# docker-compose build
# docker-compose up
```

Documentation can be found at `/admin/docs/`

Documented REST API can be found at `/pulsar/api/v1/`

## Known docker daemon issues

> ERROR: Service 'sandbox' failed to build

or

> E: Release file for http://deb.debian.org/debian/dists/buster-updates/InRelease is not valid yet (invalid for another 3d 14h 29min 34s). Updates for this repository will not be applied.
 

Issue arrises due to lack of proper time synchronization of docker daemon.

Restart your docker engine to fix this issue.

## Performance and stability issues

Please make sure your docker engine resources meet minimal hardware requirements:
- 8GB of memory
- 4 CPU cores

Recommended requirements:
- 16GB of memory
- 4 CPU

#### Experiencing unexpected crashes or scans issues during the scan?

Scanning wide domain ranges requires large amounts of memory.

- Try increasing Docker engine resources or running Pulsar on a more efficient system.
- Try upgrading your Docker engine version.

## Scan issues

Scan task debug information is stored on a web container in `/portal/logs/celery.log`
To monitor scan status you issue following command:

```
# docker-compose exec web tail -f logs/celery.log
```

In case of containers crashing during the scan, you can review docker engine logs, or monitor them with:

```
# docker stats
```

In case scans are stuck for unknown reason, you may want to check and remove broken scan and update mutex files:

```
# docker-compose exec web rm /portal/nvd/feeds/mutex
# docker-compose exec sandbox rm /opt/scan_mutex
```

In case you would like to remove broken scan you can do it in admin pannel or through REST API:

```
# curl -X DELETE https://localhost:8443/pulsar/api/v1/scans/ab6746f9-dcdc-4af9-ba0d-ac468246e10a/
```

## Web server issues

To monitor status of nginx server you may want to check its log files:

```
# docker-compose exec web tail -f /var/log/nginx/access.log
# docker-compose exec web tail -f /var/log/nginx/error.log
```

In case of REST API or Gunicorn issues you may want to review django.log:

```
# docker-compose exec web tail -f logs/django.log
```

In case you would like to configure external access, you can add additional `ALLOWED_HOSTS` in `portal/portal/settings.py` and rebuild web container.


```
# docker-compose down
# docker-compose build web
# docker-compose up
```

## Custom plugin issues

It is recommended to test custom plugins in sandbox environment before running them in the scan:

```
# docker-compose exec sandbox bash
```
