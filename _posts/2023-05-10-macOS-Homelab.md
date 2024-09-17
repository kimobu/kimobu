---
title: Adding macOS to my security homelab
date: 2023-05-10
categories: []
tags: [homelab, security, macos]
---
This post has notes on how I added a macOS machine to my security homelab.

# Install macOS to Proxmox
Follow this [guide](https://www.nicksherlock.com/2022/10/installing-macos-13-ventura-on-proxmox/) to install macOS onto a Proxmox cluster. This will result in an x86 based VM. I plan on looking into an ARM node in the future. Reference [this page](https://i12bretro.github.io/tutorials/0775.html) if you don't want to extract OSK yourself. Additional note, this installed to local-lvm, not my GlusterFS storage.

# Bind macOS to Active Directory
Since the rest of the lab is a Windows Active Directory domain, I wanted to join the macOS VM to the domain so domain users could login. Follow [the guide here](https://www.hexnode.com/blogs/macos-active-directory-binding-explained/) for high level guidance. Ventura changed the look of the Directory Utility but the overall concepts are the same. In Directory Utility, tick the option to "create mobile account at login" and add the "Users" OU to allowed administration.

I had to make sure the DC is syncing time to NTP using:  
`w32tm /config /update /manualpeerlist:"0.pool.ntp.org,0x8 1.pool.ntp.org,0x8" /syncfromflags:MANUAL` then `w32tm /resync /rediscover`

Once that was done, I made sure macOS is syncing time to the DC via:  
`sudo sntp -sS blue-dc01.blue.local`

# Security tools
Finally I wanted to install some telemetry collecting tools. Security Onion uses OSQuery and Elastic.

## Kolide launcher/osquery
OSQuery is straight forward and deployment is documented in the [Security Onion docs](https://docs.securityonion.net/en/2.3/osquery.html?highlight=macOS).

## Elastic
Elastic is a bit more complicated. Filebeats is the tool to ship logs from macOS to an Elastic stack. Follow installation instructions [here](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-installation-configuration.html) and just make sure the version of Filebeats matches the version provided by Security Onion. My Filebeat config:
```yaml
filebeat.inputs:
- type: filestream
  id: my-filestream-id
  enabled: true
  paths:
	- /var/log/*.log
- type: filestream
  id: eslogger-filestream-id
  enabled: true
  paths:
	- /var/log/eslogger.json
filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false
setup.template.settings:
  index.number_of_shards: 1
tags: ["macos"]
output.logstash:
  hosts: ["10.10.10.20:5044"]
processors:
  - add_host_metadata:
	  when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~
```

### Logs
In the Filebeat config I'm sending all the .log files from /var/log/. Only system.log is likely to be useful, but it doesn't really contain security data. The second filestream in the Filebeat config is for /var/log/eslogger.json. Apple's [Endpoint Security Framework](https://developer.apple.com/documentation/endpointsecurity) or ESF will generate data to hunt on. The ESF usage is, IMO, not ideal, so I created a script to run eslogger, `eslogger.sh` and dropped it in `/Library/Scripts`.
```shell
#!/bin/bash
: <<'END'
Events to capture:
		authentication / T1078 / valid account
		btm_launch_item_add / T1543 / persistence / sysmon 12
		btm_launch_item_remove / T1543
		create / TA0003, TA0009 / new file / sysmon 11
		deleteextattr / T1553.001 / remove quarantine
		exec / TA0002 / process creation / sysmon 1
		exit / TA0002 / process exit / sysmon 5
		kextload / T1547.001 / driver load / sysmon 6
		login_login / T1078 / valid account
		login_logout / T1078 / valid account
		mount / / mount filesystem
		openssh_login / T1078 / valid account
		openssh_logout / T1078 / valid account
		remote_thread_create / T1055 / inject process / sysmon 8
		uipc_connect / TA0010, TA0011 / networkconnect / sysmon 3
		unlink / T1070.004 / file delete / sysmon 23
		utimes / T1070.006 / timestomp / sysmon 2
		write / TA0003, TA0009 / file write / filter for persistence
		xp_malware_detected
		xp_malware_remediated
END

pids=$(ps -ef | grep eslogger | grep -v grep | grep -v bash | grep -v launchctl | awk '{ print $2 }'); for pid in $pids; do kill -9 $pid; done

/usr/bin/eslogger authentication btm_launch_item_add btm_launch_item_remove create deleteextattr exec exit kextload login_login login_logout mount openssh_login openssh_logout remote_thread_create uipc_connect unlink utimes xp_malware_detected xp_malware_remediated >> /var/log/eslogger.json
```

Now that script needs to be started. It's just appending all eslogger output to a single JSON file, and it can generate quite a bit of data. To keep my VM's disk from filling up, I wanted to rotate the log. Since I'm using a bash script to start eslogger I needed to sequence rotating the logs and restarting eslogger to have it pick up that the log file was rotated and write to the correct one. This is a hacky approach that shouldn't be used in production since there could be a one minute gap in logs.

First, create a launch daemon `eslogger.plist` that starts the script on a schedule. This daemon will run every day at 12:01AM.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.eslogger</string>
	<key>ProgramArguments</key>
	<array>
		<string>/bin/bash</string>
		<string>/Library/Scripts/eslogger.sh</string>
	</array>
	<key>StartCalendarInterval</key>
	<dict>
		<key>Hour</key>
		<integer>0</integer>
		<key>Minute</key>
		<integer>1</integer>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>UserName</key>
	<string>root</string>
	<key>StandardOutPath</key>
	<string>/tmp/com.eslogger.stdout</string>
	<key>StandardErrorPath</key>
	<string>/tmp/com.eslogger.stderr</string>
</dict>
</plist>
```

Next, edit the newsyslog config to rotate logs every day at midnight `/etc/newsyslog.d/eslogger.conf`. Log rotates at 12:00 and eslogger restarts at 12:01.
```
# logfilename           [owner:group]      mode count size(KB)  when  flags [/pid_file]          [sig_num]
/var/log/eslogger.json  :                  600  2     16384      $D0     J    
```
## Ingest pipelines
Last is to parse the eslogger output into Elastic Common Schema (ECS). I started off trying to use a Logstash pipeline but ended up with an Elasticsearch ingest pipeline. These go into `/opt/so/saltstack/local/salt/elasticsearch/files/ingest`.

First I copied SO's beats.common and added a pipeline for eslogger:  
```json
{ "pipeline":      { "if": "ctx.tags?.contains('macos')",   "name": "eslogger"  }  },
```

Then I created the eslogger pipeline. This was my first time writing an ingest pipeline. I originally tried to just write the pipeline in vim, but found that using the interface in Kibana was more helpful in getting immediate feedback on what data a document provided and how it was changed by the pipeline actions. The resulting pipeline follows. The overall flow is to copy the "message" field to "message2", then examine the keys to determine what type of ESF event was sent and categorize it. Then for each type of event, set ECS fields.
```json
{ "description": "Parse Apple's eslogger output",
   "processors": [
	   {"json": { "field": "message", "target_field": "message2",  "tag": "eslogger-json"}  },
	   {"set": {  "field": "event.code",  "value": "{{message2.event_type}}"}  },
	   {"set": {  "field": "event.module",  "value": "eslogger"}  },
	   {"set": {  "field": "observer.name",  "value": "{{host.hostname}}"}  },
	   {"set": {  "field": "event.category",  "value": "host,file",  "if": "ctx.message2.event.containsKey('create')"}  },
	   {"set": {  "field": "event.category",  "value": "host,process",  "if": "ctx.message2.event.containsKey('exec')"}  },
	   {"set": {  "field": "event.category",  "value": "host,launch_item", "if": "ctx.message2.event.containsKey('btm_launch_item_add')"  }  },
	   {"set": {  "field": "event.category",  "value": "host,file",  "if": "ctx.message2.event.containsKey('deleteextattr')"}  },
	   {"set": {  "field": "event.category",  "value": "host,process",  "if": "ctx.message2.event.containsKey('exit')"}  },
	   {"set": {  "field": "event.category",  "value": "host,account",  "if": "ctx.message2.event.containsKey('authentication')"}},
	   {"set": {  "field": "event.category",  "value": "host,driver","if": "ctx.message2.event.containsKey('kextload')"  }  },
	   {"set": {  "field": "event.category",  "value": "host,account",  "if": "ctx.message2.event.containsKey('login_login')"}},
	   {"set": {  "field": "event.category",  "value": "host,account",  "if": "ctx.message2.event.containsKey('login_logout')"}},
	   {"set": {  "field": "event.category",  "value": "host,filesystem",  "if": "ctx.message2.event.containsKey('mount')"}},
	   {"set": {  "field": "event.category",  "value": "host,account",  "if": "ctx.message2.event.containsKey('openssh_login')"}},
	   {"set": {  "field": "event.category",  "value": "host,account",  "if": "ctx.message2.event.containsKey('openssh_logout')"}},
	   {"set": {  "field": "event.category",  "value": "host,process",  "if": "ctx.message2.event.containsKey('remote_thread_create')"}},
	   {"set": {  "field": "event.category",  "value": "host,file",  "if": "ctx.message2.event.containsKey('unlink')"}},
	   {"set": {  "field": "event.category",  "value": "host,file",  "if": "ctx.message2.event.containsKey('utimes')"}},
	   {"set": {  "field": "event.category",  "value": "host,file",  "if": "ctx.message2.event.containsKey('write')"}},
	   {"set": {  "field": "event.category",  "value": "host,file",  "if": "ctx.message2.event.containsKey('xp_malware_detected')"}},
	   {"set": {  "field": "event.category",  "value": "host,file",  "if": "ctx.message2.event.containsKey('xp_malware_remediated')"}},
	   { "set":    { "if": "ctx.message2.event.containsKey('create')",  "field": "event.dataset",   "value": "file_create",         "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('exec')",   "field": "event.dataset",   "value": "process_creation",        "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('btm_launch_item_add')",   "field": "event.dataset",   "value": "btm_launch_item_add",        "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('deleteextattr')",   "field": "event.dataset",   "value": "process_changed_file",        "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('exit')",   "field": "event.dataset",   "value": "process_terminated",        "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('authentication')",   "field": "event.dataset",   "value": "authentication",        "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('kextload')",   "field": "event.dataset",   "value": "driver_loaded",        "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('login_login')",   "field": "event.dataset",   "value": "user_login",        "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('login_logout')",   "field": "event.dataset",   "value": "user_logout",        "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('mount')",   "field": "event.dataset",   "value": "filesystem_mounted",        "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('openssh_login')",   "field": "event.dataset",   "value": "user_login",        "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('openssh_logout')",   "field": "event.dataset",   "value": "user_logout",        "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('remote_thread_create')",   "field": "event.dataset",   "value": "create_remote_thread",        "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('unlink')",   "field": "event.dataset",   "value": "file_delete",        "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('utimes')",   "field": "event.dataset",   "value": "process_changed_file",        "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('write')",   "field": "event.dataset",   "value": "process_changed_file",        "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('xp_malware_detected')",   "field": "event.dataset",   "value": "malware_detected",        "override": true    } },
	   { "set":    { "if": "ctx.message2.event.containsKey('xp_malware_remediated')",   "field": "event.dataset",   "value": "malware_remediated",        "override": true    } },
	   {"rename": {  "field": "message2.event.exec.args",  "target_field": "process.command_line",  "ignore_missing": true,  "ignore_failure": true}  },
	   {"rename": {  "field": "message2.event.exec.target.executable.path",  "target_field": "process.executable",  "ignore_missing": true,  "ignore_failure": true}  },
	   {"rename": {  "field": "message2.process.audit_token.pid",  "target_field": "process.pid",  "ignore_missing": true,  "ignore_failure": true}  },
	   {"rename": {  "field": "message2.process.executable.path",  "target_field": "process.executable",  "ignore_missing": true,  "ignore_failure": true}  },
	   {"rename": {  "field": "message2.event.exec.target.signing_id",  "target_field": "process.macho.company",  "ignore_missing": true,  "ignore_failure": true}  },
	   {"rename": {  "field": "message2.process.parent_audit_token.pid",  "target_field": "process.ppid",  "ignore_missing": true,  "ignore_failure": true}  },
	   {"rename": {  "field": "message2.event.exec.cwd.path",  "target_field": "process.working_directory",  "ignore_missing": true,  "ignore_failure": true}  },
	   {"rename": {  "field": "message2.process.audit_token.euid",  "target_field": "user.id",  "ignore_missing": true,  "ignore_failure": true}  },
	   {"rename": {  "field": "message2.event.create.destination.existing_file.path","target_field": "file.target","ignore_missing": true,"ignore_failure": true  }},
	   {"rename": {  "field": "message2.event.btm_launch_item_add.item","target_field": "maclog.event_data.launch_item","ignore_missing": true,"ignore_failure": true  }},
	   {"rename": {  "field": "message2.event.btm_launch_item_add.executable_path","target_field": "maclog.event_data.launch_item.executable","ignore_missing": true,"ignore_failure": true  }},
	   {"rename": {  "field": "message2.event.btm_launch_item_remove.item","target_field": "maclog.event_data.launch_item","ignore_missing": true,"ignore_failure": true  }},
	   {"rename": {  "field": "message2.event.btm_launch_item_remove.executable_path","target_field": "maclog.event_data.launch_item.executable","ignore_missing": true, "ignore_failure": true  }},
	   {"rename": {  "field": "message2.event.unlink.target.path","target_field": "file.target","ignore_missing": true,"ignore_failure": true  }},
	   {"remove": {  "field": "message2",  "ignore_missing": true}  }]
``` 

With all that set up, I can see the parsed events in Kibana and start hunting!

![eslogger output in Kibana](/assets/img/eslogger-elastic.png)