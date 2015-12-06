simp\_le
========

|Build Status|

Simple `Let’s Encrypt`_ client.

.. code:: shell

    simp_le --email you@example.com \
      -f fullchain.pem -f key.pem \
      -d example.com -d www.example.com --default_root /var/www/html \
      -d other.com:/var/www/other_html

For more info see ``simp_le --help``.

Manifest
--------

1.  `UNIX philosophy`_: Do one thing and do it well!

2.  ``simp_le --valid_min ${seconds?} -f cert.pem`` implies that
    ``cert.pem`` is valid for at at least ``valid_min``. Register new
    ACME CA account if necessary. Issue new certificate if no previous
    key/certificate/chain found. Renew only if necessary.

3.  (Sophisticated) “manager” for
    ``${webroot?}/.well-known/acme-challenge`` only. No challenges other
    than ``http-01``. Existing web-server must be running already.

4.  No magical webserver auto-configuration.

5.  Owner of ``${webroot?}/.well-known/acme-challenge`` must be able to
    run the script, without privilege escalation (``sudo``, ``root``,
    etc.).

6.  ``crontab`` friendly: fully automatable - no prompts, etc.

7.  No configuration files. CLI flags as the sole interface! Users
    should write their own wrapper scripts or use shell aliases if
    necessary.

8.  Support multiple domains with multiple roots. Always create single
    SAN certificate per ``simp_le`` run.

9.  Flexible storage capabilities. Built-in
    ``simp_le -f fullchain.pem    -f key.pem``,
    ``simp_le -f chain.pem -f cert.pem -f key.pem``, etc. Extensions
    through ``simp_le -f external_pem.sh``.

10. Do not allow specifying output file paths. Users should symlink if
    necessary!

11. No need to allow specifying an arbitrary command when renewal has
    happened, just check the exit code:

    -  ``0`` if certificate data was created or updated;
    -  ``1`` if renewal not necessary;
    -  ``2`` in case of errors.

12. ``--server`` (support multiple CAs).

13. Support for revocation.

Installation
------------

.. code:: shell

    sudo ./bootstrap.sh
    ./venv.sh
    . venv/bin/activate

Help
----

Have a look into ``./examples/`` and
https://github.com/kuba/simp\_le/wiki/Examples.

If you’re having problems you can chat with us on `IRC (#simp\_le at
Freenode)`_

.. _Let’s Encrypt: https://letsencrypt.org
.. _UNIX philosophy: https://en.wikipedia.org/wiki/Unix_philosophy
.. _IRC (#simp\_le at Freenode): http://webchat.freenode.net?randomnick=1&channels=%23simp_le&prompt=1

.. |Build Status| image:: https://travis-ci.org/kuba/simp_le.svg?branch=master
   :target: https://travis-ci.org/kuba/simp_le
