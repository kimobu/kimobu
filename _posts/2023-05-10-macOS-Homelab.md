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

_2024-12-27: Updated to include process.group_leader.pid and populate common usernames.
```json
[ { "json": { "field": "message", "target_field": "message2", "tag": "eslogger-json" } }, { "set": { "field": "event.code", "value": "" } }, { "set": { "field": "event.dataset", "value": "esf" } }, { "set": { "field": "observer.name", "value": "" } }, { "set": { "field": "event.category", "value": "host,file", "if": "ctx.message2.event.containsKey('create')" } }, { "set": { "field": "event.category", "value": "host,process", "if": "ctx.message2.event.containsKey('exec')" } }, { "set": { "field": "event.category", "value": "host,launch_item", "if": "ctx.message2.event.containsKey('btm_launch_item_add')" } }, { "set": { "field": "event.category", "value": "host,file", "if": "ctx.message2.event.containsKey('deleteextattr')" } }, { "set": { "field": "event.category", "value": "host,process", "if": "ctx.message2.event.containsKey('exit')" } }, { "set": { "field": "event.category", "value": "host,account", "if": "ctx.message2.event.containsKey('authentication')" } }, { "set": { "field": "event.category", "value": "host,driver", "if": "ctx.message2.event.containsKey('kextload')" } }, { "set": { "field": "event.category", "value": "host,account", "if": "ctx.message2.event.containsKey('login_login')" } }, { "set": { "field": "event.category", "value": "host,account", "if": "ctx.message2.event.containsKey('login_logout')" } }, { "set": { "field": "event.category", "value": "host,filesystem", "if": "ctx.message2.event.containsKey('mount')" } }, { "set": { "field": "event.category", "value": "host,account", "if": "ctx.message2.event.containsKey('openssh_login')" } }, { "set": { "field": "event.category", "value": "host,account", "if": "ctx.message2.event.containsKey('openssh_logout')" } }, { "set": { "field": "event.category", "value": "host,process", "if": "ctx.message2.event.containsKey('remote_thread_create')" } }, { "set": { "field": "event.category", "value": "host,file", "if": "ctx.message2.event.containsKey('unlink')" } }, { "set": { "field": "event.category", "value": "host,file", "if": "ctx.message2.event.containsKey('utimes')" } }, { "set": { "field": "event.category", "value": "host,file", "if": "ctx.message2.event.containsKey('write')" } }, { "set": { "field": "event.category", "value": "host,file", "if": "ctx.message2.event.containsKey('xp_malware_detected')" } }, { "set": { "field": "event.category", "value": "host,file", "if": "ctx.message2.event.containsKey('xp_malware_remediated')" } }, { "set": { "field": "event.action", "value": "creation", "if": "ctx.message2.event.containsKey('create')" } }, { "set": { "field": "event.action", "value": "exec", "if": "ctx.message2.event.containsKey('exec')" } }, { "set": { "if": "ctx.message2.event.containsKey('btm_launch_item_add')", "field": "event.action", "value": "btm_launch_item_add", "override": true } }, { "set": { "if": "ctx.message2.event.containsKey('deleteextattr')", "field": "event.action", "value": "process_changed_file", "override": true } }, { "set": { "field": "event.action", "value": "end", "if": "ctx.message2.event.containsKey('exit')" } }, { "set": { "if": "ctx.message2.event.containsKey('authentication')", "field": "event.action", "value": "authentication", "override": true } }, { "set": { "if": "ctx.message2.event.containsKey('kextload')", "field": "event.action", "value": "driver_loaded", "override": true } }, { "set": { "if": "ctx.message2.event.containsKey('login_login')", "field": "event.action", "value": "user_login", "override": true } }, { "set": { "if": "ctx.message2.event.containsKey('login_logout')", "field": "event.action", "value": "user_logout", "override": true } }, { "set": { "if": "ctx.message2.event.containsKey('mount')", "field": "event.action", "value": "filesystem_mounted", "override": true } }, { "set": { "if": "ctx.message2.event.containsKey('openssh_login')", "field": "event.action", "value": "user_login", "override": true } }, { "set": { "if": "ctx.message2.event.containsKey('openssh_logout')", "field": "event.action", "value": "user_logout", "override": true } }, { "set": { "if": "ctx.message2.event.containsKey('remote_thread_create')", "field": "event.action", "value": "create_remote_thread", "override": true } }, { "set": { "field": "event.action", "value": "deletion", "if": "ctx.message2.event.containsKey('unlink')" } }, { "set": { "field": "event.action", "value": "modification", "if": "ctx.message2.event.containsKey('utimes')" } }, { "set": { "field": "event.action", "value": "overwrite", "if": "ctx.message2.event.containsKey('write')" } }, { "set": { "if": "ctx.message2.event.containsKey('xp_malware_detected')", "field": "event.action", "value": "malware_detected", "override": true } }, { "set": { "if": "ctx.message2.event.containsKey('xp_malware_remediated')", "field": "event.action", "value": "malware_remediated", "override": true } }, { "set": { "field": "event.action", "value": "ipc_connect", "if": "ctx.message2.event.containsKey('uipc_connect')", "ignore_failure": true } }, { "set": { "field": "event.action", "value": "ipc_bind", "if": "ctx.message2.event.containsKey('uipc_bind')", "ignore_failure": true } }, { "script": { "source": "ctx['process'] = [:];\nif (ctx.containsKey('message2') && ctx.message2.containsKey('event') && ctx.message2.event.containsKey('exec') && ctx.message2.event.exec.containsKey('args')) {\n ctx['process']['command_line'] = String.join(\" \", ctx.message2.event.exec.args);\n def cmd = ctx.message2.event.exec.args[0];\n def parts = cmd.splitOnToken(\"/\");\n def name = parts[parts.length -1];\n ctx['process']['name'] = name;\n}", "if": "ctx.message2?.event.containsKey('exec')", "ignore_failure": true, "description": "Set process.name and process.command_line" } }, { "script": { "source": "if (ctx.containsKey('message2') && ctx.message2.containsKey('event') && ctx.message2.event.containsKey('exec') && ctx.message2.event.exec.containsKey('env')) {\n for (String envVar : ctx.message2.event.exec.env) {\n int separatorIndex = envVar.indexOf('=');\n if (separatorIndex != -1) {\n String key = envVar.substring(0, separatorIndex);\n String value = envVar.substring(separatorIndex + 1);\n if (!ctx.containsKey('process')) {\n ctx['process'] = [:];\n }\n if (!ctx.process.containsKey('env')) {\n ctx.process['env'] = [:];\n }\n ctx.process.env[key] = value;\n }\n }\n}", "if": "ctx.message2?.event.containsKey('exec')", "ignore_failure": true, "description": "Set process.env" } }, { "script": { "source": "def userId = ctx['message2']['process']['audit_token']['euid'];\nctx['user'] = [:];\nctx['user']['id'] = userId.toString();\nif(userId == 829194527) {ctx['user']['name'] = \"michael.scott\";}\nelse if(userId == 793828581) {ctx['user']['name'] = \"sadiq.khan\";}\nelse if(userId == 0) {ctx['user']['name'] = \"root\";}\nelse if(userId == 200) {ctx['user']['name'] = \"_softwareupdate\";}\nelse if(userId == -2) {ctx[\"user\"][\"name\"] = \"nobody\"}\nelse if(userId == 0) {ctx[\"user\"][\"name\"] = \"root\"}\nelse if(userId == 1) {ctx[\"user\"][\"name\"] = \"daemon\"}\nelse if(userId == 4) {ctx[\"user\"][\"name\"] = \"_uucp\"}\nelse if(userId == 13) {ctx[\"user\"][\"name\"] = \"_taskgated\"}\nelse if(userId == 24) {ctx[\"user\"][\"name\"] = \"_networkd\"}\nelse if(userId == 25) {ctx[\"user\"][\"name\"] = \"_installassistant\"}\nelse if(userId == 26) {ctx[\"user\"][\"name\"] = \"_lp\"}\nelse if(userId == 27) {ctx[\"user\"][\"name\"] = \"_postfix\"}\nelse if(userId == 31) {ctx[\"user\"][\"name\"] = \"_scsd\"}\nelse if(userId == 32) {ctx[\"user\"][\"name\"] = \"_ces\"}\nelse if(userId == 33) {ctx[\"user\"][\"name\"] = \"_appstore\"}\nelse if(userId == 54) {ctx[\"user\"][\"name\"] = \"_mcxalr\"}\nelse if(userId == 55) {ctx[\"user\"][\"name\"] = \"_appleevents\"}\nelse if(userId == 56) {ctx[\"user\"][\"name\"] = \"_geod\"}\nelse if(userId == 59) {ctx[\"user\"][\"name\"] = \"_devdocs\"}\nelse if(userId == 60) {ctx[\"user\"][\"name\"] = \"_sandbox\"}\nelse if(userId == 65) {ctx[\"user\"][\"name\"] = \"_mdnsresponder\"}\nelse if(userId == 67) {ctx[\"user\"][\"name\"] = \"_ard\"}\nelse if(userId == 70) {ctx[\"user\"][\"name\"] = \"_www\"}\nelse if(userId == 71) {ctx[\"user\"][\"name\"] = \"_eppc\"}\nelse if(userId == 72) {ctx[\"user\"][\"name\"] = \"_cvs\"}\nelse if(userId == 73) {ctx[\"user\"][\"name\"] = \"_svn\"}\nelse if(userId == 74) {ctx[\"user\"][\"name\"] = \"_mysql\"}\nelse if(userId == 75) {ctx[\"user\"][\"name\"] = \"_sshd\"}\nelse if(userId == 76) {ctx[\"user\"][\"name\"] = \"_qtss\"}\nelse if(userId == 77) {ctx[\"user\"][\"name\"] = \"_cyrus\"}\nelse if(userId == 78) {ctx[\"user\"][\"name\"] = \"_mailman\"}\nelse if(userId == 79) {ctx[\"user\"][\"name\"] = \"_appserver\"}\nelse if(userId == 82) {ctx[\"user\"][\"name\"] = \"_clamav\"}\nelse if(userId == 83) {ctx[\"user\"][\"name\"] = \"_amavisd\"}\nelse if(userId == 84) {ctx[\"user\"][\"name\"] = \"_jabber\"}\nelse if(userId == 87) {ctx[\"user\"][\"name\"] = \"_appowner\"}\nelse if(userId == 88) {ctx[\"user\"][\"name\"] = \"_windowserver\"}\nelse if(userId == 89) {ctx[\"user\"][\"name\"] = \"_spotlight\"}\nelse if(userId == 91) {ctx[\"user\"][\"name\"] = \"_tokend\"}\nelse if(userId == 92) {ctx[\"user\"][\"name\"] = \"_securityagent\"}\nelse if(userId == 93) {ctx[\"user\"][\"name\"] = \"_calendar\"}\nelse if(userId == 94) {ctx[\"user\"][\"name\"] = \"_teamsserver\"}\nelse if(userId == 95) {ctx[\"user\"][\"name\"] = \"_update_sharing\"}\nelse if(userId == 96) {ctx[\"user\"][\"name\"] = \"_installer\"}\nelse if(userId == 97) {ctx[\"user\"][\"name\"] = \"_atsserver\"}\nelse if(userId == 98) {ctx[\"user\"][\"name\"] = \"_ftp\"}\nelse if(userId == 99) {ctx[\"user\"][\"name\"] = \"_unknown\"}\nelse if(userId == 200) {ctx[\"user\"][\"name\"] = \"_softwareupdate\"}\nelse if(userId == 202) {ctx[\"user\"][\"name\"] = \"_coreaudiod\"}\nelse if(userId == 203) {ctx[\"user\"][\"name\"] = \"_screensaver\"}\nelse if(userId == 205) {ctx[\"user\"][\"name\"] = \"_locationd\"}\nelse if(userId == 208) {ctx[\"user\"][\"name\"] = \"_trustevaluationagent\"}\nelse if(userId == 210) {ctx[\"user\"][\"name\"] = \"_timezone\"}\nelse if(userId == 211) {ctx[\"user\"][\"name\"] = \"_lda\"}\nelse if(userId == 212) {ctx[\"user\"][\"name\"] = \"_cvmsroot\"}\nelse if(userId == 213) {ctx[\"user\"][\"name\"] = \"_usbmuxd\"}\nelse if(userId == 214) {ctx[\"user\"][\"name\"] = \"_dovecot\"}\nelse if(userId == 215) {ctx[\"user\"][\"name\"] = \"_dpaudio\"}\nelse if(userId == 216) {ctx[\"user\"][\"name\"] = \"_postgres\"}\nelse if(userId == 217) {ctx[\"user\"][\"name\"] = \"_krbtgt\"}\nelse if(userId == 218) {ctx[\"user\"][\"name\"] = \"_kadmin_admin\"}\nelse if(userId == 219) {ctx[\"user\"][\"name\"] = \"_kadmin_changepw\"}\nelse if(userId == 220) {ctx[\"user\"][\"name\"] = \"_devicemgr\"}\nelse if(userId == 221) {ctx[\"user\"][\"name\"] = \"_webauthserver\"}\nelse if(userId == 222) {ctx[\"user\"][\"name\"] = \"_netbios\"}\nelse if(userId == 224) {ctx[\"user\"][\"name\"] = \"_warmd\"}\nelse if(userId == 227) {ctx[\"user\"][\"name\"] = \"_dovenull\"}\nelse if(userId == 228) {ctx[\"user\"][\"name\"] = \"_netstatistics\"}\nelse if(userId == 229) {ctx[\"user\"][\"name\"] = \"_avbdeviced\"}\nelse if(userId == 230) {ctx[\"user\"][\"name\"] = \"_krb_krbtgt\"}\nelse if(userId == 231) {ctx[\"user\"][\"name\"] = \"_krb_kadmin\"}\nelse if(userId == 232) {ctx[\"user\"][\"name\"] = \"_krb_changepw\"}\nelse if(userId == 233) {ctx[\"user\"][\"name\"] = \"_krb_kerberos\"}\nelse if(userId == 234) {ctx[\"user\"][\"name\"] = \"_krb_anonymous\"}\nelse if(userId == 235) {ctx[\"user\"][\"name\"] = \"_assetcache\"}\nelse if(userId == 236) {ctx[\"user\"][\"name\"] = \"_coremediaiod\"}\nelse if(userId == 239) {ctx[\"user\"][\"name\"] = \"_launchservicesd\"}\nelse if(userId == 240) {ctx[\"user\"][\"name\"] = \"_iconservices\"}\nelse if(userId == 241) {ctx[\"user\"][\"name\"] = \"_distnote\"}\nelse if(userId == 242) {ctx[\"user\"][\"name\"] = \"_nsurlsessiond\"}\nelse if(userId == 244) {ctx[\"user\"][\"name\"] = \"_displaypolicyd\"}\nelse if(userId == 245) {ctx[\"user\"][\"name\"] = \"_astris\"}\nelse if(userId == 246) {ctx[\"user\"][\"name\"] = \"_krbfast\"}\nelse if(userId == 247) {ctx[\"user\"][\"name\"] = \"_gamecontrollerd\"}\nelse if(userId == 248) {ctx[\"user\"][\"name\"] = \"_mbsetupuser\"}\nelse if(userId == 249) {ctx[\"user\"][\"name\"] = \"_ondemand\"}\nelse if(userId == 251) {ctx[\"user\"][\"name\"] = \"_xserverdocs\"}\nelse if(userId == 252) {ctx[\"user\"][\"name\"] = \"_wwwproxy\"}\nelse if(userId == 253) {ctx[\"user\"][\"name\"] = \"_mobileasset\"}\nelse if(userId == 254) {ctx[\"user\"][\"name\"] = \"_findmydevice\"}\nelse if(userId == 257) {ctx[\"user\"][\"name\"] = \"_datadetectors\"}\nelse if(userId == 258) {ctx[\"user\"][\"name\"] = \"_captiveagent\"}\nelse if(userId == 259) {ctx[\"user\"][\"name\"] = \"_ctkd\"}\nelse if(userId == 260) {ctx[\"user\"][\"name\"] = \"_applepay\"}\nelse if(userId == 261) {ctx[\"user\"][\"name\"] = \"_hidd\"}\nelse if(userId == 262) {ctx[\"user\"][\"name\"] = \"_cmiodalassistants\"}\nelse if(userId == 263) {ctx[\"user\"][\"name\"] = \"_analyticsd\"}\nelse if(userId == 265) {ctx[\"user\"][\"name\"] = \"_fpsd\"}\nelse if(userId == 266) {ctx[\"user\"][\"name\"] = \"_timed\"}\nelse if(userId == 268) {ctx[\"user\"][\"name\"] = \"_nearbyd\"}\nelse if(userId == 269) {ctx[\"user\"][\"name\"] = \"_reportmemoryexception\"}\nelse if(userId == 270) {ctx[\"user\"][\"name\"] = \"_driverkit\"}\nelse if(userId == 271) {ctx[\"user\"][\"name\"] = \"_diskimagesiod\"}\nelse if(userId == 272) {ctx[\"user\"][\"name\"] = \"_logd\"}\nelse if(userId == 273) {ctx[\"user\"][\"name\"] = \"_appinstalld\"}\nelse if(userId == 274) {ctx[\"user\"][\"name\"] = \"_installcoordinationd\"}\nelse if(userId == 275) {ctx[\"user\"][\"name\"] = \"_demod\"}\nelse if(userId == 277) {ctx[\"user\"][\"name\"] = \"_rmd\"}\nelse if(userId == 278) {ctx[\"user\"][\"name\"] = \"_accessoryupdater\"}\nelse if(userId == 279) {ctx[\"user\"][\"name\"] = \"_knowledgegraphd\"}\nelse if(userId == 280) {ctx[\"user\"][\"name\"] = \"_coreml\"}\nelse if(userId == 281) {ctx[\"user\"][\"name\"] = \"_sntpd\"}\nelse if(userId == 282) {ctx[\"user\"][\"name\"] = \"_trustd\"}\nelse if(userId == 283) {ctx[\"user\"][\"name\"] = \"_mmaintenanced\"}\nelse if(userId == 284) {ctx[\"user\"][\"name\"] = \"_darwindaemon\"}\nelse if(userId == 285) {ctx[\"user\"][\"name\"] = \"_notification_proxy\"}\nelse if(userId == 288) {ctx[\"user\"][\"name\"] = \"_avphidbridge\"}\nelse if(userId == 289) {ctx[\"user\"][\"name\"] = \"_biome\"}\nelse if(userId == 291) {ctx[\"user\"][\"name\"] = \"_backgroundassets\"}\nelse if(userId == 293) {ctx[\"user\"][\"name\"] = \"_mobilegestalthelper\"}\nelse if(userId == 294) {ctx[\"user\"][\"name\"] = \"_audiomxd\"}\nelse if(userId == 295) {ctx[\"user\"][\"name\"] = \"_terminusd\"}\nelse if(userId == 296) {ctx[\"user\"][\"name\"] = \"_neuralengine\"}\nelse if(userId == 297) {ctx[\"user\"][\"name\"] = \"_eligibilityd\"}\nelse if(userId == 298) {ctx[\"user\"][\"name\"] = \"_systemstatusd\"}\nelse if(userId == 300) {ctx[\"user\"][\"name\"] = \"_aonsensed\"}\nelse if(userId == 301) {ctx[\"user\"][\"name\"] = \"_modelmanagerd\"}\nelse if(userId == 302) {ctx[\"user\"][\"name\"] = \"_reportsystemmemory\"}\nelse if(userId == 303) {ctx[\"user\"][\"name\"] = \"_swtransparencyd\"}\nelse if(userId == 304) {ctx[\"user\"][\"name\"] = \"_naturallanguaged\"}\nelse if(userId == 441) {ctx[\"user\"][\"name\"] = \"_oahd\"}", "if": "ctx.message2.containsKey('process')", "ignore_failure": true, "description": "Set user.name based on id" } }, { "rename": { "field": "message2.event.exec.target.cdhash", "target_field": "process.macho.cdhash", "ignore_missing": true, "if": "ctx.message2?.event.containsKey('exec')", "ignore_failure": true } }, { "rename": { "field": "message2.event.exec.target.team_id", "target_field": "process.macho.team_id", "ignore_missing": true, "if": "ctx.message2?.event.containsKey('exec')", "ignore_failure": true } }, { "rename": { "field": "message2.event.exec.target.session_id", "target_field": "process.session_leader.pid", "ignore_missing": true, "ignore_failure": true } }, { "rename": { "field": "message2.event.exec.target.executable.path", "target_field": "process.executable", "ignore_missing": true, "ignore_failure": true } }, { "rename": { "field": "message2.event.exec.target.audit_token.pid", "target_field": "process.pid", "ignore_missing": true, "ignore_failure": true } }, { "rename": { "field": "message2.event.exec.target.group_id", "target_field": "process.group_leader.pid", "ignore_missing": true, "ignore_failure": true } }, { "rename": { "field": "message2.event.exec.target.original_ppid", "target_field": "process.parent.original_pid", "ignore_missing": true, "ignore_failure": true } }, { "rename": { "field": "message2.process.parent_audit_token.pid", "target_field": "process.parent.pid", "ignore_missing": true, "ignore_failure": true } }, { "rename": { "field": "message2.event.exec.target.executable.path", "target_field": "process.executable", "ignore_missing": true, "ignore_failure": true } }, { "rename": { "field": "message2.event.exec.target.signing_id", "target_field": "process.macho.company", "ignore_missing": true, "ignore_failure": true } }, { "rename": { "field": "message2.event.exec.cwd.path", "target_field": "process.working_directory", "ignore_missing": true, "ignore_failure": true } }, { "rename": { "field": "message2.event.create.destination.existing_file.path", "target_field": "file.target", "ignore_missing": true, "ignore_failure": true } }, { "rename": { "field": "message2.event.btm_launch_item_add.item", "target_field": "maclog.event_data.launch_item", "ignore_missing": true, "ignore_failure": true } }, { "rename": { "field": "message2.event.btm_launch_item_add.executable_path", "target_field": "maclog.event_data.launch_item.executable", "ignore_missing": true, "ignore_failure": true } }, { "rename": { "field": "message2.event.btm_launch_item_remove.item", "target_field": "maclog.event_data.launch_item", "ignore_missing": true, "ignore_failure": true } }, { "rename": { "field": "message2.event.btm_launch_item_remove.executable_path", "target_field": "maclog.event_data.launch_item.executable", "ignore_missing": true, "ignore_failure": true } }, { "rename": { "field": "message2.event.unlink.target.path", "target_field": "file.target", "ignore_missing": true, "ignore_failure": true } }, { "rename": { "field": "message2.process.executable.path", "target_field": "process.parent.name", "ignore_missing": true, "ignore_failure": true } }, { "remove": { "field": "message2", "ignore_missing": true, "ignore_failure": true } } ]
``` 

With all that set up, I can see the parsed events in Kibana and start hunting!

![eslogger output in Kibana](/assets/img/eslogger-elastic.png)