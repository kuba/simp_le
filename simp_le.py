#!/usr/bin/env python
#
# Simple Let's Encrypt client.
#
# Copyright (C) 2015  Jakub Warmuz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
"""Simple Let's Encrypt client."""
import abc
import argparse
import collections
import datetime
import doctest
import hashlib
import errno
import logging
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import unittest

import six
from six.moves import zip  # pylint: disable=redefined-builtin

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import mock
import OpenSSL
import pytz
import requests

from acme import client as acme_client
from acme import crypto_util
from acme import challenges
from acme import errors as acme_errors
from acme import jose
from acme import messages


# pylint: disable=too-many-lines


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

VERSION = '0'
URL = 'https://github.com/kuba/simp_le'

LE_PRODUCTION_URI = 'https://acme-v01.api.letsencrypt.org/directory'
# https://letsencrypt.org/2015/11/09/why-90-days.html
LE_CERT_VALIDITY = 90 * 24 * 60 * 60
DEFAULT_VALID_MIN = LE_CERT_VALIDITY / 3

EXIT_RENEWAL = EXIT_TESTS_OK = EXIT_REVOKE_OK = 0
EXIT_NO_RENEWAL = 1
EXIT_ERROR = 2


class Error(Exception):
    """simp_le error."""


class TestCase(unittest.TestCase):
    """simp_le unit test case."""


def gen_pkey(bits):
    """Generate a private key.

    >>> gen_pkey(1024)
    <OpenSSL.crypto.PKey object at 0x...>

    Args:
      bits: Bit size of the key.

    Returns:
      Freshly generated private key.
    """
    assert bits >= 1024  # XXX
    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(OpenSSL.crypto.TYPE_RSA, bits)
    return pkey


def gen_csr(pkey, domains, sig_hash="sha256"):
    """Generate a CSR.

    >>> crypto_util._pyopenssl_cert_or_req_san(
    ...     gen_csr(gen_pkey(1024), [b'example.com', b'example.net']))
    ['example.com', 'example.net']

    Args:
      pkey: Private key.
      domains: List of domains included in the cert.
      sig_hash: Hash used to sign the CSR.

    Returns:
      Generated CSR.
    """
    assert domains, "Must provide one or more hostnames for the CSR."
    req = OpenSSL.crypto.X509Req()
    req.add_extensions([
        OpenSSL.crypto.X509Extension(
            b"subjectAltName",
            critical=False,
            value=b", ".join(b"DNS:" + d for d in domains)
        ),
    ])
    req.set_pubkey(pkey)
    req.sign(pkey, sig_hash)
    return req


class ComparablePKey(object):  # pylint: disable=too-few-public-methods
    """Comparable key.

    Suppose you have the following keys with the same material:

    >>> pem = OpenSSL.crypto.dump_privatekey(
    ...     OpenSSL.crypto.FILETYPE_PEM, gen_pkey(1024))
    >>> k1 = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, pem)
    >>> k2 = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, pem)

    Unfortunately, in pyOpenSSL, equality is not well defined:

    >>> k1 == k2
    False

    Using `ComparablePKey` you get the equality relation right:

    >>> ck1, ck2 = ComparablePKey(k1), ComparablePKey(k2)
    >>> other_ckey = ComparablePKey(gen_pkey(1024))
    >>> ck1 == ck2
    True
    >>> ck1 == k1
    False
    >>> k1 == ck1
    False
    >>> other_ckey == ck1
    False

    Non-equalty is also well defined:

    >>> ck1 != ck2
    False
    >>> ck1 != k1
    True
    >>> k1 != ck1
    True
    >>> k1 != other_ckey
    True
    >>> other_ckey != ck1
    True

    Wrapepd key is available as well:

    >>> ck1.wrapped is k1
    True

    Internal implementation is not optimized for performance!
    """
    def __init__(self, wrapped):
        self.wrapped = wrapped

    def __ne__(self, other):
        return not self == other  # pylint: disable=unneeded-not

    def _dump(self):
        return OpenSSL.crypto.dump_privatekey(
            OpenSSL.crypto.FILETYPE_ASN1, self.wrapped)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        # pylint: disable=protected-access
        return self._dump() == other._dump()


def detect_and_log_mismatch(names, existing, requested, log_data=lambda x: x):
    """Detect and log mismatch."""
    if existing != requested:
        logger.error('Existing (%s) and requested (%s) %s mismatch',
                     log_data(existing), log_data(requested), names)
        return True
    else:
        return False


class Vhost(collections.namedtuple('Vhost', 'name root')):
    """Vhost: domain name and public html root."""
    _SEP = ':'

    @classmethod
    def decode(cls, data):
        """Decode vhost.

        >>> Vhost.decode('example.com')
        Vhost(name='example.com', root=None)
        >>> Vhost.decode('example.com:/var/www/html')
        Vhost(name='example.com', root='/var/www/html')
        >>> Vhost.decode(Vhost(name='example.com', root=None))
        Vhost(name='example.com', root=None)
        """
        if isinstance(data, cls):
            return data
        parts = data.split(cls._SEP, 1)
        parts.append(None)
        return cls(name=parts[0], root=parts[1])


class IOPlugin(object):
    """Input/output plugin.

    In case of any problems, `persisted`, `load` and `save`
    methods should raise `Error`, for which message will be
    displayed directly to the user through STDERR (in `main`).

    """
    __metaclass__ = abc.ABCMeta

    Data = collections.namedtuple('IOPluginData', 'account_key key cert chain')
    """Plugin data.

    Unless otherwise stated, plugin data components are typically
    filled with the following data:

    - for `account_key`: private account key, an instance of `acme.jose.JWK`
    - for `key`: private key, an instance of `OpenSSL.crypto.PKey`
    - for `cert`: certificate, an instance of `OpenSSL.crypto.X509`
    - for `chain`: certificate chain, a list of `OpenSSL.crypto.X509` instances
    """

    EMPTY_DATA = Data(account_key=None, key=None, cert=None, chain=None)

    def __init__(self, path, **dummy_kwargs):
        self.path = path

    @abc.abstractmethod
    def persisted(self):
        """Which data is persisted by this plugin?

        This method must be overridden in subclasses and must return
        `IOPlugin.Data` with Boolean values indicating whether specific
        component is persisted by the plugin.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def load(self):
        """Load persisted data.

        This method must be overridden in subclasses and must return
        `IOPlugin.Data`. For all non-persisted data it must set the
        corresponding component to `None`. If the data was not persisted
        previously, it must return `EMPTY_DATA` (note that it does not
        make sense for the plugin to set subset of the persisted
        components to not-None: this would mean that data was persisted
        only partially - if possible plugin should detect such condition
        and throw an `Error`).
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def save(self, data):
        """Save data to file system.

        This method must be overridden in subclasses and must accept
        `IOPlugin.Data`. It must store all persisted components and
        ignore all non-persisted components. It is guaranteed that all
        persisted components are not `None`.
        """
        raise NotImplementedError()

    # Plugin registration magic
    registered = {}

    @classmethod
    def register(cls, **kwargs):
        """Register IO plugin."""
        def init_and_reg(plugin_cls):
            """Initialize plugin class and register."""
            plugin = plugin_cls(**kwargs)
            assert (os.path.sep not in plugin.path and
                    plugin.path not in ('.', '..'))
            cls.registered[plugin.path] = plugin
            return plugin_cls
        return init_and_reg


class FileIOPlugin(IOPlugin):
    """Plugin that saves/reads files on disk."""

    READ_MODE = 'rb'
    WRITE_MODE = 'wb'

    def load(self):
        logger.debug('Loading %s', self.path)
        try:
            with open(self.path, self.READ_MODE) as persist_file:
                content = persist_file.read()
        except IOError as error:
            if error.errno == errno.ENOENT:
                # file does not exist, so it was not persisted
                # previously
                return self.EMPTY_DATA
            raise
        return self.load_from_content(content)

    @abc.abstractmethod
    def load_from_content(self, content):
        """Load from file contents.

        This method must be overridden in subclasses. It will be called
        with the contents of the file read from `path` and should return
        whatever `IOPlugin.load` is meant to return.
        """
        raise NotImplementedError()

    def save_to_file(self, data):
        """Save data to file."""
        logger.info('Saving %s', self.path)
        try:
            with open(self.path, self.WRITE_MODE) as persist_file:
                persist_file.write(data)
        except OSError as error:
            logging.exception(error)
            raise Error('Error when saving %s', self.path)


class JWKIOPlugin(IOPlugin):  # pylint: disable=abstract-method
    """IO Plugin that uses JWKs."""

    @classmethod
    def load_jwk(cls, data):
        """Load JWK."""
        return jose.JWKRSA.json_loads(data)

    @classmethod
    def dump_jwk(cls, jwk):
        """Dump JWK."""
        return jwk.json_dumps()


@IOPlugin.register(path='account_key.json')
class AccountKey(FileIOPlugin, JWKIOPlugin):
    """Account key IO Plugin using JWS."""

    # this is not a binary file
    READ_MODE = 'r'
    WRITE_MODE = 'w'

    def persisted(self):
        return self.Data(account_key=True, key=False, cert=False, chain=False)

    def load_from_content(self, content):
        return self.Data(account_key=self.load_jwk(content), key=None,
                         cert=None, chain=None)

    def save(self, data):
        return self.save_to_file(self.dump_jwk(data.account_key))


class OpenSSLIOPlugin(IOPlugin):  # pylint: disable=abstract-method
    """IOPlugin that uses pyOpenSSL.

    Args:
      typ: One of `OpenSSL.crypto.FILETYPE_*`, used in loading/dumping.
    """

    def __init__(self, typ=OpenSSL.crypto.FILETYPE_PEM, **kwargs):
        self.typ = typ
        super(OpenSSLIOPlugin, self).__init__(**kwargs)

    def load_key(self, data):
        """Load private key."""
        return ComparablePKey(OpenSSL.crypto.load_privatekey(self.typ, data))

    def dump_key(self, data):
        """Dump private key."""
        return OpenSSL.crypto.dump_privatekey(self.typ, data.wrapped).strip()

    def load_cert(self, data):
        """Load certificate."""
        return jose.ComparableX509(OpenSSL.crypto.load_certificate(
            self.typ, data))

    def dump_cert(self, data):
        """Dump certificate."""
        # pylint: disable=protected-access
        return OpenSSL.crypto.dump_certificate(self.typ, data._wrapped).strip()


@IOPlugin.register(path='external.sh', typ=OpenSSL.crypto.FILETYPE_PEM)
class ExternalIOPlugin(OpenSSLIOPlugin, JWKIOPlugin):
    """External IO Plugin.

    This plugin executes script that complies with the
    "persisted|load|save protocol":

    - whenever the script is called with `persisted` as the first
      argument, it should send to STDOUT a single line consisting of a
      subset of three keywords: `account_key`, `key`, `cart`, `chain`
      (in any order, separated by whitespace);

    - whenever the script is called with `load` as the first argument it
      shall write to STDOUT all persisted data as JWK for account key or
      otherwise PEM encoded strings separated by double newline
      characters (`\\n\\n`) in the following order: account_key, key,
      certificate, certificates in the chain (from leaf to root, also
      separated using `\\n\\n`). If some data is not persisted, it must
      be skipped in the output;

    - whenever the script is called with `save` as the first argument,
      it should accept data from STDIN and persist it. Data is encoded
      and ordered in the same way as in the `load` case.
    """

    _SEP = b'\n\n'

    @property
    def script(self):
        """Path to the script."""
        return os.path.join('.', self.path)

    def get_output_or_fail(self, command):
        """Get output or throw an exception in case of errors."""
        try:
            proc = subprocess.Popen(
                [self.script, command], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE)
        except (OSError, subprocess.CalledProcessError) as error:
            logger.exception(error)
            raise Error(
                'There was a problem executing external IO plugin script')

        stdout, stderr = proc.communicate()
        if stderr is not None:
            logger.error('STDERR: %s', stderr)
        if proc.wait():
            raise Error('External script exited with non-zero code: %d' %
                        proc.returncode)
        return stdout

    def persisted(self):
        """Call the external script and see which data is persisted."""
        output = self.get_output_or_fail('persisted').split()
        return self.Data(
            account_key=(b'account_key' in output),
            key=(b'key' in output),
            cert=(b'cert' in output),
            chain=(b'chain' in output),
        )

    def load(self):
        """Call the external script to retrieve persisted data."""
        output = self.get_output_or_fail('load').split(self._SEP)
        # Do NOT log `output` as it might contain secret material (in
        # case key is persisted)

        persisted = self.persisted()
        expected_count = len([comp for comp in persisted if comp])
        if output == [b'']:
            # no previously persisted data; NB `b''.split(b'\n\n') == [b'']`
            return self.EMPTY_DATA
        elif expected_count != len(output):
            raise Error(
                'Expected %d components (%r) from external plugin, %d '
                'received. ' % (expected_count, persisted, len(output)))

        account_key = self.load_jwk(
            output.pop(0)) if persisted.account_key else None
        key = self.load_key(output.pop(0)) if persisted.key else None
        cert = self.load_cert(output.pop(0)) if persisted.cert else None
        chain = ([self.load_cert(cert_data) for cert_data in output]
                 if persisted.chain else None)
        return self.Data(account_key=account_key, key=key,
                         cert=cert, chain=chain)

    def save(self, data):
        """Call the external script and send data to be persisted to STDIN."""
        persisted = self.persisted()
        output = []
        if persisted.account_key:
            output.append(self.dump_jwk(data.account_key))
        if persisted.key:
            output.append(self.dump_key(data.key))
        if persisted.cert:
            output.append(self.dump_cert(data.cert))
        if persisted.chain:
            output.extend(self.dump_cert(cert_data)
                          for cert_data in data.chain)

        logger.info('Calling `%s save` and piping data through', self.script)
        try:
            proc = subprocess.Popen(
                [self.script, 'save'], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE)
        except OSError as error:
            logger.exception(error)
            raise Error(
                'There was a problem executing external IO plugin script')
        stdout, stderr = proc.communicate(self._SEP.join(output))
        if stdout is not None:
            logger.debug('STDOUT: %s', stdout)
        if stderr is not None:
            logger.error('STDERR: %s', stderr)
        if proc.wait():
            raise Error('External script exited with non-zero code: %d' %
                        proc.returncode)


class ExternalIOPluginTest(TestCase):
    """Tests for ExternalIOPlugin."""

    # this is unittest suite | pylint: disable=missing-docstring

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.path = os.path.join(self.root, 'external.sh')
        self.plugin = ExternalIOPlugin(path=self.path)
        self.key_data = IOPlugin.Data(
            account_key=None, cert=None, chain=None,
            key=ComparablePKey(gen_pkey(1024)))

    def tearDown(self):
        shutil.rmtree(self.root)

    def save_script(self, contents):
        with open(self.path, 'w') as external_plugin_file:
            external_plugin_file.write(contents)
        os.chmod(self.path, 0o700)

    def test_no_persisted_empty(self):
        self.save_script('#!/bin/sh')
        self.assertEqual(IOPlugin.EMPTY_DATA, self.plugin.load())

    def test_missing_path_raises_error(self):
        self.assertRaises(Error, self.plugin.load)

    def test_non_zero_exit_raises_error(self):
        self.save_script('#!/bin/sh\nfalse')
        self.assertRaises(Error, self.plugin.load)

    def test_unexpected_load_data(self):
        self.save_script("""\
#!/bin/sh
case $1 in load) echo x;; persisted) ;; esac""")
        self.assertRaises(Error, self.plugin.load)

    def test_it(self):
        key_path = os.path.join(self.root, 'key.pem')
        self.save_script("""\
#!/bin/sh
case $1 in
  save) cat - > {key_path};;
  load) cat {key_path} || true;;
  persisted) echo key;;
esac
""".format(key_path=key_path))

        # not yet persisted
        self.assertEqual(IOPlugin.EMPTY_DATA, self.plugin.load())
        # save some data
        self.plugin.save(self.key_data)
        self.assertTrue(os.path.exists(key_path))
        # loading should return the persisted data back in
        self.assertEqual(self.key_data, self.plugin.load())


@IOPlugin.register(path='chain.der', typ=OpenSSL.crypto.FILETYPE_ASN1)
@IOPlugin.register(path='chain.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class ChainFile(FileIOPlugin, OpenSSLIOPlugin):
    """Certificate chain plugin."""

    _SEP = b'\n\n'  # TODO: do all webservers like this?

    def persisted(self):
        return self.Data(account_key=False, key=False, cert=False, chain=True)

    def load_from_content(self, output):
        chain = [self.load_cert(cert_data)
                 for cert_data in output.split(self._SEP)]
        return self.Data(account_key=None, key=None, cert=None, chain=chain)

    def save(self, data):
        return self.save_to_file(self._SEP.join(
            self.dump_cert(chain_cert) for chain_cert in data.chain))


@IOPlugin.register(path='fullchain.der', typ=OpenSSL.crypto.FILETYPE_ASN1)
@IOPlugin.register(path='fullchain.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class FullChainFile(ChainFile):
    """Full chain file plugin."""

    def persisted(self):
        return self.Data(account_key=False, key=False, cert=True, chain=True)

    def load(self):
        data = super(FullChainFile, self).load()
        if data.chain is None:
            cert, chain = None, None
        else:
            cert, chain = data.chain[0], data.chain[1:]
        return self.Data(account_key=data.account_key, key=data.key,
                         cert=cert, chain=chain)

    def save(self, data):
        return super(FullChainFile, self).save(self.Data(
            account_key=data.account_key, key=data.key,
            cert=None, chain=([data.cert] + data.chain)))


@IOPlugin.register(path='key.der', typ=OpenSSL.crypto.FILETYPE_ASN1)
@IOPlugin.register(path='key.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class KeyFile(FileIOPlugin, OpenSSLIOPlugin):
    """Private key file plugin."""

    def persisted(self):
        return self.Data(account_key=False, key=True, cert=False, chain=False)

    def load_from_content(self, output):
        return self.Data(account_key=None, key=self.load_key(output),
                         cert=None, chain=None)

    def save(self, data):
        return self.save_to_file(self.dump_key(data.key))


@IOPlugin.register(path='cert.der', typ=OpenSSL.crypto.FILETYPE_ASN1)
@IOPlugin.register(path='cert.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class CertFile(FileIOPlugin, OpenSSLIOPlugin):
    """Certificate file plugin."""

    def persisted(self):
        return self.Data(account_key=False, key=False, cert=True, chain=False)

    def load_from_content(self, output):
        return self.Data(account_key=None, key=None,
                         cert=self.load_cert(output), chain=None)

    def save(self, data):
        return self.save_to_file(self.dump_cert(data.cert))


def create_parser():
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        usage=argparse.SUPPRESS, add_help=False,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog='See %s for more info.' % URL,
    )

    general = parser.add_argument_group()
    general.add_argument(
        '-v', '--verbose', action='store_true', default=False,
        help='Increase verbosity of the logging.',
    )

    modes = parser.add_argument_group()
    modes.add_argument(
        '-h', '--help', action='help', default=argparse.SUPPRESS,
        help='Show this help message and exit.',
    )
    modes.add_argument(
        '--version', action='version', version=('%(prog)s ' + VERSION),
        help='Display version and exit.'
    )
    modes.add_argument(
        '--revoke', action='store_true', default=False,
        help='Revoke existing certificate')
    modes.add_argument(
        '--test', action='store_true', default=False,
        help='Run tests and exit.',
    )

    manager = parser.add_argument_group(
        'Webroot manager', description='This client is just a '
        'sophisticated manager for $webroot/' +
        challenges.HTTP01.URI_ROOT_PATH + '. You can (optionally) '
        'specify `--default_root`, and override per-vhost with '
        '`-d example.com:/var/www/other_html` syntax.',
    )
    manager.add_argument(
        '-d', '--vhost', dest='vhosts', action='append',
        help='Domain name that will be included in the certificate. '
        'Must be specified at least once.', metavar='DOMAIN:PATH',
        type=Vhost.decode,
    )
    manager.add_argument(
        '--default_root', help="Default webroot path.", metavar='PATH',
    )

    io_group = parser.add_argument_group('Certificate data files')
    io_group.add_argument(
        '-f', dest='ioplugins', action='append', default=[],
        metavar='PLUGIN', choices=sorted(IOPlugin.registered),
        help='Input/output plugin of choice, can be specified multiple '
        'times and, in fact, it should be specified as many times as it '
        'is necessary to cover all components: key, certificate, chain. '
        'Allowed values: %s.' % ', '.join(sorted(IOPlugin.registered)),
    )
    io_group.add_argument(
        '--cert_key_size', type=int, default=4096, metavar='BITS',
        help='Certificate key size. Fresh key is created for each renewal.',
    )
    io_group.add_argument(
        '--valid_min', type=int, default=DEFAULT_VALID_MIN, metavar='SECONDS',
        help='Minimum validity of the resulting certificate.',
    )
    io_group.add_argument(
        '--reuse_key', action='store_true', default=False,
        help='Reuse private key if it was previously persisted.',
    )

    reg = parser.add_argument_group(
        'Registration', description='This client will automatically '
        'register an account with the ACME CA specified by `--server`.'
    )
    reg.add_argument(
        '--account_key_public_exponent', type=int, default=65537,
        metavar='BITS', help='Account key public exponent value.',
    )
    reg.add_argument(
        '--account_key_size', type=int, default=4096, metavar='BITS',
        help='Account key size in bits.',
    )
    reg.add_argument(
        '--tos_sha256', help='SHA-256 hash of the contents of Terms Of '
        'Service URI contents.', default='33d233c8ab558ba6c8ebc370a509a'
        'cdded8b80e5d587aa5d192193f35226540f', metavar='HASH',
    )
    reg.add_argument(
        '--email', help='Email address. CA is likely to use it to '
        'remind about expiring certificates, as well as for account '
        'recovery. Therefore, it\'s highly recommended to set this '
        'value.',
    )

    http = parser.add_argument_group(
        'HTTP', description='Configure properties of HTTP requests and '
        'responses.',
    )
    http.add_argument(
        '--user_agent', default=('simp_le/' + VERSION), metavar='NAME',
        help='User-Agent sent in all HTTP requests. Override with '
        '--user_agent "" if you want to protect your privacy.',
    )
    http.add_argument(
        '--server', metavar='URI', default=LE_PRODUCTION_URI,
        help='Directory URI for the CA ACME API endpoint.',
    )

    return parser


def supported_challb(authorization):
    """Find supported challenge body.

    This plugin supports only `http-01`, so CA must offer it as a
    single-element combo. If this is not the case this function returns
    `None`.

    Returns:
      `acme.messages.ChallengeBody` with `http-01` challenge or `None`.
    """
    for combo in authorization.body.combinations:
        first_challb = authorization.body.challenges[combo[0]]
        if len(combo) == 1 and isinstance(
                first_challb.chall, challenges.HTTP01):
            return first_challb
    return None


def compute_roots(vhosts, default_root):
    """Compute webroots.

    Args:
      vhosts: collection of `Vhost` objects.
      default_root: Default webroot path.

    Returns:
      Dictionary mapping vhost name to its webroot path. Vhosts without
      a root will be pre-populated with the `default_root`.
    """
    roots = {}
    for vhost in vhosts:
        if vhost.root is not None:
            root = vhost.root
        else:
            root = default_root
        roots[vhost.name] = root

    empty_roots = dict((name, root)
                       for name, root in six.iteritems(roots) if root is None)
    if empty_roots:
        raise Error('Root for the following host(s) were not specified: %s. '
                    'Try --default_root or use -d example.com:/var/www/html '
                    'syntax' % ', '.join(empty_roots))
    return roots


def save_validation(root, challb, validation):
    """Save validation to webroot.

    Args:
      root: Webroot path.
      challb: `acme.messages.ChallengeBody` with `http-01` challenge.
      validation: `http-01` validation
    """
    try:
        os.makedirs(os.path.join(root, challb.URI_ROOT_PATH))
    except OSError as error:
        if error.errno != errno.EEXIST:
            # directory doesn't already exist and we cannot create it
            raise
    path = os.path.join(root, challb.path[1:])
    with open(path, 'w') as validation_file:
        logger.debug('Saving validation (%r) at %s', validation, path)
        validation_file.write(validation)


def sha256_of_uri_contents(uri, chunk_size=10):
    """Get SHA256 of URI contents.

    >>> with mock.patch('requests.get') as mock_get:
    ...     sha256_of_uri_contents('https://example.com')
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    """
    h = hashlib.sha256()  # pylint: disable=invalid-name
    response = requests.get(uri, stream=True)
    for chunk in response.iter_content(chunk_size):
        h.update(chunk)
    return h.hexdigest()


def componentwise_or(first, second):
    """Componentwise OR.

    >>> componentwise_or((False, False), (False, False))
    (False, False)
    >>> componentwise_or((True, False), (False, False))
    (True, False)
    >>> componentwise_or((True, False), (False, True))
    (True, True)
    """
    return tuple(x or y for x, y in zip(first, second))


def persist_data(args, data):
    """Persist data on disk.

    Uses all selected plugins to save certificate data to disk.
    """
    for plugin_name in args.ioplugins:
        IOPlugin.registered[plugin_name].save(data)


def asn1_generalizedtime_to_dt(timestamp):
    """Convert ASN.1 GENERALIZEDTIME to datetime.

    Useful for deserialization of `OpenSSL.crypto.X509.get_notAfter` and
    `OpenSSL.crypto.X509.get_notAfter` outputs.

    TODO: Implement remaining two formats: *+hhmm, *-hhmm.

    >>> asn1_generalizedtime_to_dt('201511150803Z')
    datetime.datetime(2015, 11, 15, 8, 0, 3, tzinfo=<UTC>)
    >>> asn1_generalizedtime_to_dt('201511150803+1512')
    datetime.datetime(2015, 11, 15, 8, 0, 3, tzinfo=pytz.FixedOffset(912))
    >>> asn1_generalizedtime_to_dt('201511150803-1512')
    datetime.datetime(2015, 11, 15, 8, 0, 3, tzinfo=pytz.FixedOffset(-912))
    """
    dt = datetime.datetime.strptime(  # pylint: disable=invalid-name
        timestamp[:12], '%Y%m%d%H%M%S')
    # tzinfo, pylint bug | pylint: disable=redefined-variable-type
    if timestamp.endswith('Z'):
        tzinfo = pytz.utc
    else:
        sign = -1 if timestamp[-5] == '-' else 1
        tzinfo = pytz.FixedOffset(
            sign * (int(timestamp[-4:-2]) * 60 + int(timestamp[-2:])))
    return tzinfo.localize(dt)


def renewal_necessary(cert, valid_min):
    """Is renewal necessary?

    >>> cert = crypto_util.gen_ss_cert(
    ...     gen_pkey(1024), ['example.com'], validity=(60 *60))
    >>> renewal_necessary(cert, 60 * 60 * 24)
    True
    >>> renewal_necessary(cert, 1)
    False
    """
    now = pytz.utc.localize(datetime.datetime.utcnow())
    expiry = asn1_generalizedtime_to_dt(cert.get_notAfter().decode())
    diff = expiry - now
    logger.debug('Certificate expires in %s on %s (relative to %s)',
                 diff, expiry, now)
    return diff < datetime.timedelta(seconds=valid_min)


def test(args):
    """Run tests (--test)."""
    suite = unittest.TestSuite((
        doctest.DocTestSuite(optionflags=(
            doctest.ELLIPSIS | doctest.IGNORE_EXCEPTION_DETAIL)),
        unittest.defaultTestLoader.loadTestsFromName(__name__)
    ))
    return EXIT_TESTS_OK if unittest.TextTestRunner(
        verbosity=(2 if args.verbose else 1)).run(
            suite).wasSuccessful() else EXIT_ERROR


def check_plugins_persist_all(ioplugins):
    """Do plugins cover all components (key/cert/chain)?"""
    persisted = IOPlugin.Data(
        account_key=False, key=False, cert=False, chain=False)
    for plugin_name in ioplugins:
        persisted = IOPlugin.Data(*componentwise_or(
            persisted, IOPlugin.registered[plugin_name].persisted()))

    not_persisted = set([
        component
        for component, persist in six.iteritems(persisted._asdict())
        if not persist])
    if not_persisted:
        raise Error('Selected IO plugins do not cover the following '
                    'components: %s.' % ', '.join(not_persisted))


def load_existing_data(ioplugins):
    """Load existing data from disk.

    Returns:
      `IOPlugin.Data` with all plugin data merged and sanity checked
      for coherence.
    """
    def merge(first, second, field):
        """Merge data from two plugins.

        >>> add(None, 1, 'foo')
        1
        >>> add(1, None, 'foo')
        1
        >>> add(None, None, 'foo')
        None
        >>> add(1, 2, 'foo')
        Error: Some plugins returned conflicting data for the "foo" component
        """
        if first is not None and second is not None and first != second:
            raise Error('Some plugins returned conflicting data for '
                        'the "%s" component' % field)
        return first or second

    all_existing = IOPlugin.EMPTY_DATA
    for plugin_name in ioplugins:
        all_persisted = IOPlugin.registered[plugin_name].persisted()
        all_data = IOPlugin.registered[plugin_name].load()

        # Check that plugins obey the interface: "`not persisted`
        # implies `data is None`" which is equivalent to `persisted or
        # data is None`
        assert all(persisted or data is None
                   for persisted, data in zip(all_persisted, all_data))

        all_existing = IOPlugin.Data(*(merge(*data) for data in zip(
            all_existing, all_data, all_data._fields)))
    return all_existing


def pyopenssl_cert_or_req_san(cert):
    """SANs from cert or csr."""
    # This function is not inlined mainly because pylint is bugged
    # when it comes to locally disabling protected access...
    # pylint: disable=protected-access
    return crypto_util._pyopenssl_cert_or_req_san(cert)


def valid_existing_cert(cert, vhosts, valid_min):
    """Is the existing cert data valid for enough time?

    >>> valid_existing_cert(None, [], 0)
    False
    >>> cert = crypto_util.gen_ss_cert(
    ...     gen_pkey(1024), ['example.com'], validity=(60 *60))
    >>> valid_existing_cert(cert, [Vhost.decode('example.com')], 0)
    True
    >>> valid_existing_cert(cert, [Vhost.decode('example.com')], 60 * 60 + 1)
    False
    >>> valid_existing_cert(cert, [Vhost.decode('example.net')], 0)
    Traceback (most recent call last):
    ...
    Error: Backup and remove existing cert if you want to proceed
    >>> valid_existing_cert(cert, [], 0)
    Traceback (most recent call last):
    ...
    Error: Backup and remove existing cert if you want to proceed
    """
    if cert is None:
        return False  # no existing certificate
    else:  # renew existing?
        sans = pyopenssl_cert_or_req_san(cert)
        logger.debug('Existing SANs: %r', sans)
        if detect_and_log_mismatch(
                'SANs', set(sans), set(vhost.name for vhost in vhosts),
                log_data=', '.join):
            raise Error(
                'Backup and remove existing cert if you want to proceed')
        return not renewal_necessary(cert, valid_min)


def check_or_generate_account_key(args, existing):
    """Check or generate account key."""
    if existing is None:
        logger.info('Generating new account key')
        return jose.JWKRSA(key=rsa.generate_private_key(
            public_exponent=args.account_key_public_exponent,
            key_size=args.account_key_size,
            backend=default_backend()
        ))

    mismatch = False
    mismatch |= detect_and_log_mismatch(
        'key sizes', existing.key.key_size, args.account_key_size)
    mismatch |= detect_and_log_mismatch(
        'public key exponents', existing.public_key().key.public_numbers().e,
        args.account_key_public_exponent)
    if mismatch:
        raise Error('Please adjust flags or backup and remove old key')
    return existing


def registered_client(args, existing_account_key):
    """Create ACME client, register if necessary."""
    key = check_or_generate_account_key(args, existing_account_key)
    net = acme_client.ClientNetwork(key, user_agent=args.user_agent)
    client = acme_client.Client(directory=args.server, key=key, net=net)
    if args.email is None:
        logger.warning('--email was not provided; ACME CA will have no '
                       'way of contacting you.')
    new_reg = messages.NewRegistration.from_data(email=args.email)
    try:
        regr = client.register(new_reg)
    except messages.Error as error:
        if error.detail != 'Registration key is already in use':
            raise
    else:
        if regr.terms_of_service is not None:
            tos_hash = sha256_of_uri_contents(regr.terms_of_service)
            logger.debug('TOS hash: %s', tos_hash)
            if args.tos_sha256 != tos_hash:
                raise Error('TOS hash mismatch. Found: %s.' % tos_hash)
            client.agree_to_tos(regr)

    return client


def get_certr(client, csr, authorizations):
    """Get Certificate Resource for specified CSR and authorizations."""
    try:
        certr, _ = client.poll_and_request_issuance(
            csr, authorizations.values(),
            # https://github.com/letsencrypt/letsencrypt/issues/1719
            max_attempts=(10 * len(authorizations)))
    except acme_errors.PollError as error:
        if error.timeout:
            logger.error('Timed out while waiting for CA to verify '
                         'challenge(s) for the following authorizations: %s',
                         ', '.join(authzr.uri for _, authzr in error.waiting))

        invalid = [authzr for authzr in six.itervalues(error.updated)
                   if authzr.body.status == messages.STATUS_INVALID]
        if invalid:
            logger.error('CA marked some of the authorizations as invalid, '
                         'which likely means it could not access '
                         'http://example.com/.well-known/acme-challenge/X. '
                         'Did you set correct path in -d example.com:path '
                         'or --default_root? Is there a warning log entry '
                         'about unsuccessful self-verification? Are all your '
                         'domains accessible from the internet? Failing '
                         'authorizations: %s',
                         ', '.join(authzr.uri for authzr in invalid))

        raise Error('Challenge validation has failed, see error log.')
    return certr


def new_data(args, existing):
    """Issue and persist new key/cert/chain."""
    roots = compute_roots(args.vhosts, args.default_root)
    logger.debug('Computed roots: %r', roots)

    client = registered_client(args, existing.account_key)

    authorizations = dict(
        (vhost.name, client.request_domain_challenges(
            vhost.name, new_authz_uri=client.directory.new_authz))
        for vhost in args.vhosts
    )
    if any(supported_challb(auth) is None
           for auth in six.itervalues(authorizations)):
        raise Error('CA did not offer http-01-only challenge combo. '
                    'This client is unable to solve any other challenges.')

    for name, auth in six.iteritems(authorizations):
        challb = supported_challb(auth)
        response, validation = challb.response_and_validation(client.key)
        save_validation(roots[name], challb, validation)

        verified = response.simple_verify(
            challb.chall, name, client.key.public_key())
        if not verified:
            logger.warning('%s was not successfully self-verified. '
                           'CA is likely to fail as well!', name)
        else:
            logger.info('%s was successfully self-verified', name)

        client.answer_challenge(challb, response)

    if args.reuse_key and existing.key is not None:
        logger.info('Reusing existing certificate private key')
        key = existing.key
    else:
        logger.info('Generating new certificate private key')
        key = ComparablePKey(gen_pkey(args.cert_key_size))
    csr = gen_csr(key.wrapped, [vhost.name.encode() for vhost in args.vhosts])
    certr = get_certr(client, csr, authorizations)
    persist_data(args, IOPlugin.Data(
        account_key=client.key, key=key,
        cert=certr.body, chain=client.fetch_chain(certr)))


def revoke(args):
    """Revoke certificate."""
    existing = load_existing_data(args.ioplugins)
    if existing.cert is None:
        raise Error('No existing certificate')

    key = check_or_generate_account_key(args, existing.account_key)
    net = acme_client.ClientNetwork(key, user_agent=args.user_agent)
    client = acme_client.Client(directory=args.server, key=key, net=net)
    client.revoke(existing.cert)
    return EXIT_REVOKE_OK


def setup_logging(verbose):
    """Setup basic logging."""
    level = logging.DEBUG if verbose else logging.INFO
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    handler = logging.StreamHandler()
    handler.setLevel(level)
    formatter = logging.Formatter(
        fmt='%(asctime)s:%(levelname)s:%(name)s:%(lineno)d: %(message)s',
    )
    formatter.converter = time.gmtime  # UTC instead of localtime
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)


def main_with_exceptions(cli_args):
    """Run the script, throw exceptions on error."""
    args = create_parser().parse_args(cli_args)

    if args.test:  # --test
        return test(args)

    setup_logging(args.verbose)
    logger.debug('%r parsed as %r', cli_args, args)

    if args.revoke:  # --revoke
        return revoke(args)

    if args.vhosts is None:
        raise Error('You must set at least one -d/--vhost')
    check_plugins_persist_all(args.ioplugins)

    existing_data = load_existing_data(args.ioplugins)
    if valid_existing_cert(existing_data.cert, args.vhosts, args.valid_min):
        logger.info('Certificates already exist and renewal is not '
                    'necessary, exiting with status code %d.', EXIT_NO_RENEWAL)
        return EXIT_NO_RENEWAL
    else:
        new_data(args, existing_data)
        return EXIT_RENEWAL


def exit_with_error(message):
    """Print `message` and debugging tips to STDERR, exit with EXIT_ERROR."""
    sys.stderr.write('%s\n\nDebugging tips: -v improves output verbosity. '
                     'Help is available under --help.\n' % message)
    raise SystemExit(EXIT_ERROR)


def main(cli_args=sys.argv[1:]):
    """Run the script, with exceptions caught and printed to STDERR."""
    # logging (handler) is not set up yet, use STDERR only!
    try:
        raise SystemExit(main_with_exceptions(cli_args))
    except Error as error:
        exit_with_error(error)
    except messages.Error as error:
        exit_with_error('ACME server returned an error: %s\n' % error)
    except Exception as error:  # pylint: disable=broad-except
        # maintain manifest invariant: `exit 1` iff renewal not
        # necessary, `exit 2` iff error
        traceback.print_exc(file=sys.stderr)
        exit_with_error('\nUnhandled error has happened, traceback is above')


class MainIntegrationTests(TestCase):
    """Integration tests for main()."""

    # this is unittest suite | pylint: disable=missing-docstring

    @mock.patch('sys.stderr')
    def test_error_exit_codes(self, dummy_stderr):
        test_args = [
            '',  # no args - no good
            '--bar',  # unrecognized
            '-f account_key.json -f key.pem -f fullchain.pem',  # no vhosts
            # no root
            '-f account_key.json -f key.pem -f fullchain.pem -d example.com',
            # no root with multiple domains
            '-f account_key.json -f key.pem -f fullchain.pem '
            '-d example.com:public_html  -d www.example.com',
        ]
        # missing plugin coverage
        test_args.extend(['-d example.com:public_html %s' % rest for rest in [
            '-f account_key.json',
            '-f key.pem',
            '-f account_key.json -f key.pem',
            '-f key.pem -f cert.pem',
            '-f key.pem -f chain.pem',
            '-f fullchain.pem',
            '-f cert.pem -f fullchain.pem',
        ]])

        for args in test_args:
            try:
                main(shlex.split(args))
            except SystemExit as error:
                self.assertEqual(EXIT_ERROR, error.code)
            else:
                # assertRaises in 2.6 is not context manager, we need
                # a way to check that this code path is not reachable
                assert False


if __name__ == '__main__':
    main()
