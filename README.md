# simp_le

Simple [Let's Encrypt](https://letsencrypt.org) client.

```shell
simp_le -f fullchain.pem -f key.pem \
  -d example.com -d www.example.com --default_root /var/www/html \
  -d other.com:/var/www/other_html
```

For more info see `simp_le --help`.

## Manifest

1. [UNIX philosophy](https://en.wikipedia.org/wiki/Unix_philosophy):
   Do one thing and do it well!

2. `simp_le --valid_min ${seconds?} -f cert.pem` implies that
   `cert.pem` is valid for at at least `valid_min`. Register new ACME
   CA account if necessary. Issue new certificate if no previous
   key/certificate/chain found. Renew only if necessary.

3. (Sophisticated) "manager" for
   `${webroot?}/.well-known/acme-challenges` only. No challenges other
   than `http-01`. Existing web-server must be running already.

4. No magical webserver auto-configuration.

5. Owner of `${webroot?}/.well-known/acme-challenges` must be able to
   run the script, without privilege escalation (`sudo`, `root`,
   etc.).

6. `crontab` friendly: fully automatable - no prompts, etc.

7. No configuration files. CLI flags as the sole interface! Users
   should write their own wrapper scripts or use shell aliases if
   necessary.

8. Support multiple domains with multiple roots. Always create single
   SAN certificate per `simp_le` run.

9. Flexible storage capabilities. Built-in `simp_le -f fullchain.pem
   -f privkey.pem`, `simp_le -f chain.pem -f cert.pem -d privkey.pem`,
   etc. Extensions through `simp_le -f external_pem.sh`.

10. Do not allow specifying output file paths. Users should symlink if
    necessary!

11. No need to allow arbitrary command when renewal has happened: just
    compare cert before and after (`sha256sum`, `mtime`, etc.).

12. `--server` (support multiple CAs).

## Installation

```shell
sudo ./bootstrap.sh
./venv.sh
. venv/bin/activate
```

## Examples

Have a look into `./examples/`.
