"""
The `~certbot_dns_clouddns.dns_clouddns` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the CloudDNS REST API.


Named Arguments
---------------

========================================  =====================================
``--dns-clouddns-credentials``            CloudDNS Remote API credentials_
                                          INI file. (Required)
``--dns-clouddns-propagation-seconds``    The number of seconds to wait for DNS
                                          to propagate before asking the ACME
                                          server to verify the DNS record.
                                          (Default: 120)
========================================  =====================================


Credentials
-----------

Use of this plugin requires a configuration file containing CloudDNS Remote API
.

Example credentials file:

.. code:: ini

   # CloudDNS API credentials used by Certbot
   dns_clouddns_clientip = myclientid
   dns_clouddns_email = myemailaddress
   dns_clouddns_password = mysecretpassword

The path to this file can be provided interactively or using the
``--dns-clouddns-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

**Caution**

   You should protect these API credentials as you would a password. Users who
   can read this file can use these to issue arbitrary CloudDNS API calls on
   your behalf. Users who can cause Certbot to run using these credentials can
   complete a ``dns-01`` challenge to acquire new certificates or revoke
   existing certificates for associated domains, even if those domains aren't
   being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).

Examples
--------

To acquire a certificate for ``example.com``

.. code:: bash

   certbot certonly \\
     --dns-clouddns \\
     --dns-clouddns-credentials ~/.secrets/certbot/clouddns.ini \\
     -d example.com

To acquire a single certificate for both ``example.com`` and ``*.example.com``

.. code:: bash

   certbot certonly \\
     --dns-clouddns \\
     --dns-clouddns-credentials ~/.secrets/certbot/clouddns.ini \\
     -d example.com \\
     -d '*.example.com'

To acquire a certificate for ``example.com``, waiting 240 seconds for DNS propagation

.. code:: bash

   certbot certonly \\
     --dns-clouddns \\
     --dns-clouddns-credentials ~/.secrets/certbot/clouddns.ini \\
     --dns-clouddns-propagation-seconds 240 \\
     -d example.com
"""