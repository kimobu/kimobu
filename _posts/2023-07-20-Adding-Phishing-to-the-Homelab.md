---
title: Putting phishing data into Security Onion
date: 2023-07-20
categories: []
tags: [homelab]
---
I wanted to add some phishing scenarios to my hunting homelab. I'm more concerned with being able to hunt on malicious emails than on stopping them, so [DMARC, DKIM, and SPF](https://www.cloudflare.com/learning/email-security/dmarc-dkim-spf/) are out of scope. If you have an offensive lens, you'll want to look at something like [this](https://www.securesystems.de/blog/building-a-red-team-infrastructure-in-2023/) for an effective phishing set up.

Let's look at two areas: external mail where phishing comes from and internal mail where phishes will be received.

# External mail
We need some infrastructure set up to send email. First is Postfix, a mail server. We can send email using a command line, but we might want to compose emails graphically, so we'll install an IMAP server (dovecot) and a webmail server (Roundcube).

## Postfix
[This guide](https://orcacore.com/install-postfix-mail-server-ubuntu-22-04/) was pretty solid to get Postfix up and running. To support SMTPS we'll need a certificate:

```
openssl req -newkey rsa:2048 -keyout /etc/ssl/private/mail-kvps.key.enc -x509 -days 365 -out mail-kvps.crt
openssl rsa -in /etc/ssl/private/mail-kvps.key.enc -out /etc/ssl/private/mail-kvps.key
```

Here's an example Postfix configuration file `main.cf`. Comments are inline.
```
smtpd_banner = $myhostname ESMTP $mail_name (Debian/GNU)
biff = no
append_dot_mydomain = no
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mydestination = mail.kvps.local, localhost.kvps.local, localhost  # What domains to receive mail for
relayhost =
mynetworks = 127.0.0.0/8 10.10.41.0/24  # What networks to relay mail from
inet_interfaces = all
recipient_delimiter = +
compatibility_level = 2
myorigin = /etc/mailname
mailbox_size_limit = 0
inet_protocols = ipv4
home_mailbox = Maildir/  # In the user's homedir, where should mail be stored
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_local_domain =
smtpd_sasl_security_options = noanonymous
smtpd_sasl_tls_security_options = noanonymous
broken_sasl_auth_clients = yes
smtpd_sasl_auth_enable = yes
smtp_tls_security_level = may
smtpd_tls_security_level = may
smtp_tls_note_starttls_offer = yes
smtpd_tls_key_file = /etc/ssl/private/mail-kvps.key  # TLS key from openssl above
smtpd_tls_cert_file = /etc/ssl/certs/mail-kvps.crt   # TlS cert from openssl above
smtpd_tls_loglevel = 4
smtpd_tls_received_header = yes
myhostname = mail.kvps.local  # Who are we
smtpd_tls_auth_only = no
tls_random_source = dev:/dev/urandom
```

## Dovecot
The dovecot install is [straight forward](https://ubuntu.com/server/docs/mail-dovecot). 

In `10-mail.conf` we set the mail_location to match Postfix:
```
mail_location = maildir:~/Maildir
```
Then in `10-master.conf` we set the auth on unix_listener:
```
unix_listener /var/spool/postfix/private/auth {
	mode = 0666
	user = postfix
	group = postfix
  }
```

In `/etc/dovecot/users` we can add in email addresses, passwords, and user maildirs:
```
admin@paypai-support.com:{PLAIN}abc123:1001:1001::/home/vmail::userdb_mail=maildir:~/Maildir/paypai-support.com/admin
```

## Roundcube
Lastly install [Roundcube](https://github.com/roundcube/roundcubemail/wiki/Installation).

In `config.inc.php` we configure the following:
```
$config['db_dsnw'] = 'mysql://USERNAME:PASSWORD@localhost/DATABASE';
$config['imap_host'] = 'localhost:143';
$config['smtp_host'] = 'localhost:25';
$config['support_url'] = 'http://localhost';
$config['des_key'] = 'YOURKEY';
$config['plugins'] = [];
$config['language'] = 'en_US';
$config['spellcheck_engine'] = 'enchant';
```

# Internal mail
Next is internal email. The lab is Active Directory based, so I use Exchange.

## Exchange
Pull the Windows Server 2019 Standard ISO from the Microsoft EvalCenter and the Exchange 2019 ISO from [here](https://www.microsoft.com/en-us/download/details.aspx?id=104131).
In my server (VM) I added a 100Gb drive and installed Exchange to it in D:\exchange.

Once installed, configure the Exchange server to do nothing with malicious emails.

# DNS
Now to send emails from External to Internal, we need to set up some DNS MX entries. On a container I run bind and configure the following in `named.conf.local`:
```
zone "kvps.local" {
	type master;
	file "/etc/bind/db.kvps.local";
};

zone "41.10.10.in-addr.arpa" {
	type master;
	file "/etc/bind/db.10";
};

zone "blue.local" {
	type master;
	file "/etc/bind/db.blue.local";
};
```

Then in `db.kvps.local` we set up records for the external mail server:
```
$TTL    604800
@       IN      SOA     kvps.local. root.kvps.local. (
							  4         ; Serial
						 604800         ; Refresh
						  86400         ; Retry
						2419200         ; Expire
						 604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.kvps.local.
@       IN      A       10.10.41.103
ns      IN      A       10.10.41.103
@       IN      AAAA    ::1
@       IN      MX  1   mail.kvps.local.
mail    IN      A       10.10.41.102
```

And in `db.blue.local` we set up records for the internal mail server:
```
$TTL    604800
@       IN      SOA     blue.local. root.blue.local. (
							  2         ; Serial
						 604800         ; Refresh
						  86400         ; Retry
						2419200         ; Expire
						 604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.blue.local.
@       IN      A       10.10.41.103
ns      IN      A       10.10.41.103
@       IN      AAAA    ::1
@       IN      MX  1   mail.blue.local.
mail    IN      A       10.10.41.100
```

Finally we create reverse zone records for the lab in `db.10`:
```
$TTL    604800
@       IN      SOA     ns.kvps.local. root.ns.kvps.local. (
							  2         ; Serial
						 604800         ; Refresh
						  86400         ; Retry
						2419200         ; Expire
						 604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.kvps.local.
@       IN      PTR     kvps.local.
mail    IN      A       10.10.41.102
ns      IN      A       10.10.41.103
@       IN      MX      102     mail.kvps.local.
103.10.10       IN      PTR     ns.kvps.local.


@       IN      SOA     ns.blue.local. root.ns.blue.local. (
							  2         ; Serial
						 604800         ; Refresh
						  86400         ; Retry
						2419200         ; Expire
						 604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.blue.local.
@       IN      PTR     blue.local.
mail    IN      A       10.10.41.100
ns      IN      A       10.10.41.103
@       IN      MX      100     mail.blue.local.
103.10.10       IN      PTR     ns.blue.local.
```

We can test that email gets sent with telnet:
```
telnet mail.blue.local 25
MAIL FROM:<newsletter@contoso.com>
RCPT TO:<victim@blue.local>
DATA
Subject: Test from Contoso
This is a test message
```

# Security Onion
Now that we can send and receive email, lets add some data to Security Onion.
## Security Onion 2.3
### Zeek
Zeek has plugins that let you parse email messages. One I included was smtp-url-analysis, which will extract links from email and track whether those links were visited. To add this to Security Onion's Zeek container, we do:
```
mkdir -p /opt/so/saltstack/local/salt/zeek/policy/custom
cd /tmp
git clone https://github.com/initconf/smtp-url-analysis.git
mv smtp-url-analysis/scripts/ /opt/so/saltstack/local/salt/zeek/policy/custom/
```
Then we configure `/opt/so/saltstack/local/pillar/minions/$SENSORNAME_$ROLE.sls`:
```
zeek:
  local:
    '@load':
      - custom/smtp_url/scripts
```
### Filebeat
Once Zeek is configured, we need Filebeat to pull in the dataset by adding the following to  `/opt/so/saltstack/local/pillar/zeeklogs.sls`:
```
	- smtpurl_links
```
### Elasticsearch
Finally, we need to parse data out of the Zeek logs via an Elasticsearch ingest pipeline. Create a file at `/opt/so/saltstack/local/salt/elasticsearch/files/ingest/smtp_urls` with:
```
 {
	"description" : "zeek.smtpurl_links",
	"processors" : [
	  { "remove":         { "field": ["host"],     "ignore_failure": true                                                                  } },
	  { "json":       { "field": "message",           "target_field": "message2",     "ignore_failure": true  } },
	  { "rename":     { "field": "message2.host",  "target_field": "smtp.url.host",       "ignore_missing": true  } },
	  { "rename":     { "field": "message2.url",  "target_field": "smtp.url.url",       "ignore_missing": true  } },
	  { "pipeline":       { "name": "zeek.common"                                                                                   } }
	]
  }
```

## Security Onion 2.4
SO2.4 has changed how some things are configured.
### Zeek
We still pull this down as previously:
```
mkdir -p /opt/so/saltstack/local/salt/zeek/policy/custom
cd /tmp
git clone https://github.com/initconf/smtp-url-analysis.git
mv smtp-url-analysis/scripts/ /opt/so/saltstack/local/salt/zeek/policy/custom/
```
Then in SOC, navigate to Configuration -> zeek -> config -> local -> load. For your node, add `custom/scripts` as a script to be loaded.

### Elastic Fleet
The Elastic Agent/Fleet replace Filebeat. The Fleet pulls the logs from `/nsm/zeek/logs/current/*.log` and uses an exclude list. We do not need to change anything here.

### Elasticsearch
This should be mostly the same. I used the name zeek.smtpurl_links to conform with the `zeek-logs` agent policy.