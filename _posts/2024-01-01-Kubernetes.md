---
title: Learning Kubernetes
date: 2024-01-01
categories: []
tags: [homelab]
---

I run a few services for the threat intelligence and hunting course that I teach, including [CAPE](https://github.com/kevoreilly/CAPEv2), [MISP](https://www.misp-project.org), and [Caldera](https://caldera.mitre.org). Last semester, I used a few VMs and Docker to provide these, but I wanted to learn Kubernetes. Here are some notes on migrating over.

# Getting Started

I started trying Kubernetes the hard way but ultimately ended up using [microk8s](https://microk8s.io/#install-microk8s). The install guide was straight forward. I made 1x control plane node and 2x worker nodes. I used [this blog](https://www.robert-jensen.dk/posts/2021-microk8s-with-traefik-and-metallb/) as a starting point. I used Robert's suggestion for `nfs-subdir-external-provisioner` to provide the persistent storage for my pods.

One of the first things I looked at was providing access to the services. I previously used Nginx as a reverse proxy, and sent requests to each service based on the hostname requested. For example, going to misp.jhu-ctih.training sent the students to the MISP server. With Kubernetes, I learned about [LoadBalancers](https://kubernetes.io/docs/concepts/services-networking/ingress/#load-balancing) to do the same thing. Since I self-host I used [MetalLB](https://metallb.org). This was setup with one line: `microk8s enable metallb:<start_ip>-<end_ip>`. Instead of Nginx, I used Traefik. 

# Adding services
MISP and Caldera provide Docker files. I used [Kompose](https://kompose.io) to convert those to Kubernetes YAML files.

## MISP
The [misp-docker](https://github.com/MISP/misp-docker) project uses four containers: misp-core, misp-modules, mariadb, and redis. Kompose converted those into four deployments, four services, and four persistent volume claims. I had some issues with the mariadb container, so I used the [Bitnami MariaDB](https://bitnami.com/stack/mariadb/helm) Helm Chart. I specify the database variables in the values YAML:

```
  extraEnvVars:
- name: MARIADB_DATABASE
  value: <database_name>
- name: MARIADB_PASSWORD
  value: <user_password>
- name: MARIADB_ROOT_PASSWORD
  value: <root_password>
- name: MARIADB_USER
  value: <username>
```

I condensed the misp-core container into one file with both a Deployment and a Service. Make sure the MYSQL_* variables match the MARIADB_* variables from above.

```
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
	kompose.cmd: kompose --file docker-compose.yml convert
	kompose.version: 1.26.0 (40646f47)
  creationTimestamp: null
  labels:
	io.kompose.service: misp-core
  name: misp-core
  namespace: misp
spec:
  replicas: 1
  selector:
	matchLabels:
	  io.kompose.service: misp-core
  strategy:
	type: Recreate
  template:
	metadata:
	  annotations:
		kompose.cmd: kompose --file docker-compose.yml convert
		kompose.version: 1.26.0 (40646f47)
	  creationTimestamp: null
	  labels:
		io.kompose.service: misp-core
	spec:
	  containers:
		- env:
			- name: ADMIN_EMAIL
			  value: <misp_admin_email>
			- name: ADMIN_PASSWORD
			  value: <misp_admin_password>
			- name: BASE_URL
			  value: https://misp.jhu-ctih.training
			- name: MYSQL_DATABASE
			  value: <database_name>
			- name: MYSQL_HOST
			  value: misp-db-mariadb # internal Kubernetes networking resolution
			- name: MYSQL_PASSWORD
			  value: <user_password>
			- name: MYSQL_PORT
			  value: "3306"
			- name: MYSQL_USER
			  value: <username>
			- name: REDIS_FQDN
			  value: misp-redis  # internal Kubernetes networking resolution
			- name: SYNCSERVERS_1_DATA
			  value: |2

				{
				  "remote_org_uuid": "",
				  "name": "",
				  "authkey": "",
				  "url": "",
				  "pull": true
				}
		  image: ghcr.io/misp/misp-docker/misp-core:latest
		  name: misp-core
		  ports:
			- containerPort: 80
			- containerPort: 443
		  resources: {}
		  volumeMounts:
			- mountPath: /var/www/MISP/app/Config/
			  name: misp-core-config
			- mountPath: /var/www/MISP/app/tmp/logs/
			  name: misp-core-logs
			- mountPath: /var/www/MISP/app/files/
			  name: misp-core-files
			- mountPath: /etc/nginx/certs/
			  name: misp-core-certs
			- mountPath: /var/www/MISP/.gnupg/
			  name: misp-core-gnupg
	  restartPolicy: Always
	  volumes:
		- name: misp-core-config
		  nfs:
			server: <nfs_servername>
			path: /nfs_storage/kube/misp/www-data/app/Config
		- name: misp-core-logs
		  nfs:
			server: <nfs_servername>
			path: /nfs_storage/kube/misp/www-data/app/tmp/logs
		- name: misp-core-files
		  nfs:
			server: <nfs_servername>
			path: /nfs_storage/kube/misp/www-data/app/files
		- name: misp-core-certs
		  nfs:
			server: <nfs_servername>
			path: /nfs_storage/kube/misp/www-data/nginx/certs
		- name: misp-core-gnupg
		  nfs:
			server: <nfs_servername>
			path: /nfs_storage/kube/misp/www-data/gnupg
status: {}
---
apiVersion: v1
kind: Service
metadata:
  annotations:
	kompose.cmd: kompose --file docker-compose.yml convert
	kompose.version: 1.26.0 (40646f47)
  creationTimestamp: null
  labels:
	io.kompose.service: misp-core
  name: misp-core
  namespace: misp
spec:
  ports:
	- name: "80"
	  port: 80
	  targetPort: 80
	- name: "443"
	  port: 443
	  targetPort: 443
  selector:
	io.kompose.service: misp-core
status:
  loadBalancer: {}
```

The manifests for misp-modules and redis worked without modification.

## Caldera
The manifests created by Kompose tried to pull caldera:latest, but the image does not exist. Caldera uses Docker RUN to set up the container. I changed the image to ubuntu:latest, and used a [ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/) to define a shell script the implements all of the RUN commands to do the container setup.

```
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
	kompose.cmd: kompose convert
	kompose.version: 1.31.2 (a92241f79)
  creationTimestamp: null
  labels:
	io.kompose.service: caldera
  name: caldera
  namespace: caldera
spec:
  replicas: 1
  selector:
	matchLabels:
	  io.kompose.service: caldera
  strategy:
	type: Recreate
  template:
	metadata:
	  annotations:
		kompose.cmd: kompose convert
		kompose.version: 1.31.2 (a92241f79)
	  creationTimestamp: null
	  labels:
		io.kompose.network/caldera-default: "true"
		io.kompose.service: caldera
	spec:
	  containers:
		- image: ubuntu:latest
		  name: caldera
		  command: ["/bin/entrypoint.sh"]
		  volumeMounts:
			- name: caldera-app
			  mountPath: /usr/src/app
			- name: configmap-volume
			  mountPath: /bin/entrypoint.sh
			  readOnly: true
			  subPath: entrypoint.sh
		  env:
			- name: VIRTUAL_ENV
			  value: /opt/venv/caldera
			- name: TZ
			  value: UTC
			- name: WIN_BUILD
			  value: "true"
		  workingDir: /usr/src/app
		  ports:
			- containerPort: 8888
			  hostPort: 8888
			  protocol: TCP
			- containerPort: 8443
			  hostPort: 8443
			  protocol: TCP
			- containerPort: 7010
			  hostPort: 7010
			  protocol: TCP
			- containerPort: 7011
			  hostPort: 7011
			  protocol: UDP
			- containerPort: 7012
			  hostPort: 7012
			  protocol: TCP
			- containerPort: 8853
			  hostPort: 8853
			  protocol: TCP
			- containerPort: 8022
			  hostPort: 8022
			  protocol: TCP
			- containerPort: 2222
			  hostPort: 2222
			  protocol: TCP
		  resources: {}
	  restartPolicy: Always
	  volumes:
		- name: caldera-app
		  nfs:
			server: <nfs_servername>
			path: /nfs_storage/kube/caldera/caldera
		- name: configmap-volume
		  configMap:
			defaultMode: 0700
			name: configmap-caldera
status: {}
```

Here's the ConfigMap:

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: configmap-caldera
  namespace: caldera
data:
  entrypoint.sh: |
	#!/bin/bash
	function initCaldera {
	  if [ -z "$(ls plugins/stockpile)" ]; then echo "stockpile plugin not downloaded - please ensure you recursively cloned the caldera git repository and try again."; exit 1; fi
	  apt-get update && apt-get -y install python3 python3-pip python3-venv git curl golang-go
	  if [ "$WIN_BUILD" = "true" ] ; then apt-get -y install mingw-w64; fi
	  python3 -m venv $VIRTUAL_ENV
	  PATH="$VIRTUAL_ENV/bin:$PATH"
	  pip3 install --no-cache-dir -r requirements.txt
	  python3 -c "import app; import app.utility.config_generator; app.utility.config_generator.ensure_local_config();"
	  sed -i '/\- atomic/d' conf/local.yml
	  cd /usr/src/app/plugins/sandcat/gocat
	  go mod tidy && go mod download
	  cd /usr/src/app/plugins/sandcat
	  if [ "$WIN_BUILD" = "true" ] ; then 
		cp ./update-agents.sh ./update-agents-copy.sh
	  fi
	  if [ "$WIN_BUILD" = "true" ] ; 
		then tr -d '\15\32' < ./update-agents-copy.sh > ./update-agents.sh
	  fi
	  if [ "$WIN_BUILD" = "true" ] ; then 
		rm ./update-agents-copy.sh
	  fi
	  ./update-agents.sh
	  mkdir /tmp/gocatextensionstest
	  cp -R ./gocat /tmp/gocatextensionstest/gocat
	  cp -R ./gocat-extensions/* /tmp/gocatextensionstest/gocat/
	  cp ./update-agents.sh /tmp/gocatextensionstest/update-agents.sh
	  cd /tmp/gocatextensionstest
	  mkdir /tmp/gocatextensionstest/payloads
	  ./update-agents.sh
	  if [ ! -d "/usr/src/app/plugins/atomic/data/atomic-red-team" ]; then 
		git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git; /usr/src/app/plugins/atomic/data/atomic-red-team
	  fi
	  cd /usr/src/app/plugins/emu
	  if [ $(grep -c "\- emu" ../../conf/local.yml)  ]; then
		apt-get -y install zlib1g unzip; pip3 install -r requirements.txt
		./download_payloads.sh
	  fi
	  touch /usr/src/app/.configured
	}
	if [ ! -f /usr/src/app/.configured ]; then 
	  initCaldera
	fi
	PATH="$VIRTUAL_ENV/bin:$PATH"
	cd /usr/src/app
	python3 server.py --log DEBUG
```

## CAPE
CAPE did not get converted to Kubernetes since it still needs to run VMs to detonate malware.

## Exposing Services
The MISP and Caldera servers are now available within the Kubernetes network. To expose them, I deploy Traefik IngressRoutes. An IngressRoute is also used to pass cape.jhu-ctih.training to an ExternalService.

I applied some custom configurations to Traefik. MISP uses a self-signed certificate which Traefik will not validate. I request a specific IP from MetalLB. Each service runs in its own namespace, so I allow cross-namespace access. Since CAPE is an external service to the Kubernetes cluster, I allow external name service access.

```
service:
  enabled: true
  single: true
  type: LoadBalancer
  spec: {}
  loadBalancerIP: "<requested_ip_in_metallb_range>"
providers:
	kubernetesCRD:
	  enabled: true
	  allowCrossNamespace: true
	  allowExternalNameServices: true
additionalArguments: 
	- --serverstransport.insecureskipverify=true
```
Then for each service, create an IngressRoute:

```
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: jhu-ctih-https
spec:
  entryPoints:
	- websecure
  routes:
	- match: Host(`misp.jhu-ctih.training`)
	  kind: Rule
	  services:
		- name: misp-core
		  port: 443
		  namespace: misp
---
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: jhu-ctih-https
spec:
  entryPoints:
	- websecure
  routes:
	- match: Host(`caldera.jhu-ctih.training`)
	  kind: Rule
	  services:
		- name: caldera
		  port: 8888
		  namespace: caldera
---
kind: Service
apiVersion: v1
metadata:
  name: cape-service
spec:
  type: ExternalName
  ports:
	- port: 8000  # This port and the port below must match
  externalName: <cape_server_ip>
---
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: cape-ingress
spec:
  entryPoints:
	- websecure
  routes:
	- match: Host(`cape.jhu-ctih.training`)
	  kind: Rule
	  priority: 1
	  services:
		- name: cape-service
		  port: 8000  # Thought this was Traefik listen port, but must match above
```