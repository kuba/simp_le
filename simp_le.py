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
import contextlib
import datetime
import doctest
import hashlib
import errno
import logging
import os
import re
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
from cryptography.hazmat.primitives import serialization
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

EXIT_RENEWAL = EXIT_TESTS_OK = EXIT_REVOKE_OK = EXIT_HELP_VERSION_OK = 0
EXIT_NO_RENEWAL = 1
EXIT_ERROR = 2


class Error(Exception):
    """simp_le error."""


class UnitTestCase(unittest.TestCase):
    """simp_le unit test case."""

    class AssertRaisesContext(object):
        """Context for assert_raises."""
        # pylint: disable=too-few-public-methods

        def __init__(self):
            self.error = None

    @contextlib.contextmanager
    def assert_raises(self, exc):
        """Assert raises context manager."""
        context = self.AssertRaisesContext()
        try:
            yield context
        except exc as error:
            context.error = error
        else:
            self.fail('Expected exception (%s) not raised' % exc)

    def assert_raises_regexp(self, exc, regexp, func, *args, **kwargs):
        """Assert raises that tests exception message against regexp."""
        with self.assert_raises(exc) as context:
            func(*args, **kwargs)
        msg = str(context.error)
        self.assertTrue(re.match(regexp, msg) is not None,
                        "Exception message (%s) doesn't match "
                        "regexp (%s)" % (msg, regexp))

    def assert_raises_error(self, *args, **kwargs):
        """Assert raises simp_le error with given message."""
        self.assert_raises_regexp(Error, *args, **kwargs)


_PEM_RE_LABELCHAR = r'[\x21-\x2c\x2e-\x7e]'
_PEM_RE = re.compile(
    (r"""
^-----BEGIN\ ((?:%s(?:[- ]?%s)*)?)\s*-----$
.*?
^-----END\ \1-----\s*""" % (_PEM_RE_LABELCHAR, _PEM_RE_LABELCHAR)).encode(),
    re.DOTALL | re.MULTILINE | re.VERBOSE)
_PEMS_SEP = b'\n'


def split_pems(buf):
    r"""Split buffer comprised of PEM encoded (RFC 7468).

    >>> x = b'\n-----BEGIN FOO BAR-----\nfoo\nbar\n-----END FOO BAR-----'
    >>> len(list(split_pems(x * 3)))
    3
    >>> list(split_pems(b''))
    []
    """
    for match in _PEM_RE.finditer(buf):
        yield match.group(0)


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


def gen_csr(pkey, domains, sig_hash='sha256'):
    """Generate a CSR.

    >>> [str(domain) for domain in crypto_util._pyopenssl_cert_or_req_san(
    ...     gen_csr(gen_pkey(1024), [b'example.com', b'example.net']))]
    ['example.com', 'example.net']

    Args:
      pkey: Private key.
      domains: List of domains included in the cert.
      sig_hash: Hash used to sign the CSR.

    Returns:
      Generated CSR.
    """
    assert domains, 'Must provide one or more hostnames for the CSR.'
    req = OpenSSL.crypto.X509Req()
    req.add_extensions([
        OpenSSL.crypto.X509Extension(
            b'subjectAltName',
            critical=False,
            value=b', '.join(b'DNS:' + d for d in domains)
        ),
    ])
    req.set_pubkey(pkey)

    # pre-1.0.2 version of OpenSSL the generated CSR will contain a
    # zero-length Version field which will cause some strict parsers
    # (e.g. the one in Golang, used by Boulder) to fail.
    req.set_version(2)

    req.sign(pkey, sig_hash)
    return req


class IOPlugin(object):
    """Input/output plugin.

    In case of any problems, `persisted`, `load` and `save` methods
    should raise `Error`, for which message will be displayed directly
    to the user through STDERR (in `main`).

    """
    __metaclass__ = abc.ABCMeta

    Data = collections.namedtuple('IOPluginData', 'account_key csr cert chain')
    """Plugin data.

    Unless otherwise stated, plugin data components are typically
    filled with the following data:

    - for `account_key`: private account key, an instance of `acme.jose.JWK`
    - for `csr`: Certificate Signing Request, an instance of
      `OpenSSL.crypto.X509` wrapped in `acme.jose.ComparableX509`
    - for `cert`: certificate, an instance of `OpenSSL.crypto.X509`
      wrapped in `acme.jose.ComparableX509`
    - for `chain`: certificate chain, a list of `OpenSSL.crypto.X509`
      instances wrapped in `acme.jose.ComparableX509`
    """

    EMPTY_DATA = Data(account_key=None, csr=None, cert=None, chain=None)

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
        return self.Data(account_key=True, csr=False, cert=False, chain=False)

    def load_from_content(self, content):
        return self.Data(account_key=self.load_jwk(content), csr=None,
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

    def load_csr(self, data):
        """Load CSR."""
        return jose.ComparableX509(OpenSSL.crypto.load_certificate_request(
            self.typ, data))

    def dump_csr(self, data):
        """Dump CSR."""
        # pylint: disable=protected-access
        return OpenSSL.crypto.dump_certificate_request(
            self.typ, data.wrapped).strip()

    def load_cert(self, data):
        """Load certificate."""
        return jose.ComparableX509(OpenSSL.crypto.load_certificate(
            self.typ, data))

    def dump_cert(self, data):
        """Dump certificate."""
        return OpenSSL.crypto.dump_certificate(self.typ, data.wrapped).strip()


def load_pem_jwk(data):
    """Load JWK encoded as PEM."""
    return jose.JWKRSA(key=serialization.load_pem_private_key(
        data, password=None, backend=default_backend()))


def dump_pem_jwk(data):
    """Dump JWK as PEM."""
    return data.key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).strip()


@IOPlugin.register(path='external.sh', typ=OpenSSL.crypto.FILETYPE_PEM)
class ExternalIOPlugin(OpenSSLIOPlugin):
    """External IO Plugin.

    This plugin executes script that complies with the
    "persisted|load|save protocol":

    - whenever the script is called with `persisted` as the first
      argument, it should send to STDOUT a single line consisting of a
      subset of three keywords: `account_key`, `csr`, `cart`, `chain`
      (in any order, separated by whitespace);

    - whenever the script is called with `load` as the first argument it
      shall write to STDOUT all persisted data as PEM encoded strings in
      the following order: account_key, csr, certificate, certificates
      in the chain (from leaf to root). If some data is not persisted,
      it must be skipped in the output;

    - whenever the script is called with `save` as the first argument,
      it should accept data from STDIN and persist it. Data is encoded
      and ordered in the same way as in the `load` case.
    """

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
            raise Error('Failed to execute external script: %s' % error)

        stdout, stderr = proc.communicate()
        if stderr is not None:
            logger.error('STDERR: %s', stderr)
        if proc.wait():
            raise Error('External script exited with non-zero code: %d' %
                        proc.returncode)

        # invariant: STDOUT will not contain any secret material
        logger.debug('STDOUT: %s', stdout)
        return stdout

    def persisted(self):
        """Call the external script and see which data is persisted."""
        output = self.get_output_or_fail('persisted').split()
        return self.Data(
            account_key=(b'account_key' in output),
            csr=(b'csr' in output),
            cert=(b'cert' in output),
            chain=(b'chain' in output),
        )

    def load(self):
        """Call the external script to retrieve persisted data."""
        pems = list(split_pems(self.get_output_or_fail('load')))
        if not pems:
            return self.EMPTY_DATA
        persisted = self.persisted()

        account_key = load_pem_jwk(
            pems.pop(0)) if persisted.account_key else None
        csr = self.load_csr(pems.pop(0)) if persisted.csr else None
        cert = self.load_cert(pems.pop(0)) if persisted.cert else None
        chain = ([self.load_cert(cert_data) for cert_data in pems]
                 if persisted.chain else None)
        return self.Data(account_key=account_key, csr=csr,
                         cert=cert, chain=chain)

    def save(self, data):
        """Call the external script and send data to be persisted to STDIN."""
        persisted = self.persisted()
        output = []
        if persisted.account_key:
            output.append(dump_pem_jwk(data.account_key))
        if persisted.csr:
            output.append(self.dump_csr(data.csr))
        if persisted.cert:
            output.append(self.dump_cert(data.cert))
        if persisted.chain:
            output.extend(self.dump_cert(cert) for cert in data.chain)

        logger.info('Calling `%s save` and piping data through', self.script)
        try:
            proc = subprocess.Popen(
                [self.script, 'save'], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE)
        except OSError as error:
            logger.exception(error)
            raise Error(
                'There was a problem executing external IO plugin script')
        stdout, stderr = proc.communicate(_PEMS_SEP.join(output))
        if stdout is not None:
            logger.debug('STDOUT: %s', stdout)
        if stderr is not None:
            logger.error('STDERR: %s', stderr)
        if proc.wait():
            raise Error('External script exited with non-zero code: %d' %
                        proc.returncode)


class PluginIOTestMixin(object):
    """Common plugins tests."""
    # this is a test suite | pylint: disable=missing-docstring

    PLUGIN_CLS = NotImplemented

    def __init__(self, *args, **kwargs):
        super(PluginIOTestMixin, self).__init__(*args, **kwargs)

        raw_key = gen_pkey(1024)
        self.all_data = IOPlugin.Data(
            account_key=jose.JWKRSA(key=rsa.generate_private_key(
                public_exponent=65537, key_size=1024,
                backend=default_backend(),
            )),
            csr=jose.ComparableX509(gen_csr(raw_key, [b'example.com'])),
            cert=jose.ComparableX509(crypto_util.gen_ss_cert(raw_key, ['a'])),
            chain=[
                jose.ComparableX509(crypto_util.gen_ss_cert(raw_key, ['b'])),
                jose.ComparableX509(crypto_util.gen_ss_cert(raw_key, ['c'])),
            ],
        )

    def setUp(self):  # pylint: disable=invalid-name
        self.root = tempfile.mkdtemp()
        self.path = os.path.join(self.root, 'plugin')
        # pylint: disable=not-callable
        self.plugin = self.PLUGIN_CLS(path=self.path)

    def tearDown(self):  # pylint: disable=invalid-name
        shutil.rmtree(self.root)


class FileIOPluginTestMixin(PluginIOTestMixin):
    """Common FileIO plugins tests."""
    # this is a test suite | pylint: disable=missing-docstring

    def test_empty(self):
        self.assertEqual(IOPlugin.EMPTY_DATA, self.plugin.load())

    def test_save_ignore_unpersisted(self):
        self.plugin.save(self.all_data)
        self.assertEqual(self.plugin.load(), IOPlugin.Data(
            *(data if persist else None for persist, data in
              zip(self.plugin.persisted(), self.all_data))))


class ExternalIOPluginTest(PluginIOTestMixin, UnitTestCase):
    """Tests for ExternalIOPlugin."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = ExternalIOPlugin

    def save_script(self, contents):
        with open(self.path, 'w') as external_plugin_file:
            external_plugin_file.write(contents)
        os.chmod(self.path, 0o700)

    def test_no_persisted_empty(self):
        self.save_script('#!/bin/sh')
        self.assertEqual(IOPlugin.EMPTY_DATA, self.plugin.load())

    def test_missing_path_raises_error(self):
        self.assert_raises_error(
            'Failed to execute external script', self.plugin.load)

    def test_load_nonzero_raises_error(self):
        self.save_script('#!/bin/sh\nfalse')
        self.assert_raises_error(
            '.*exited with non-zero code: 1', self.plugin.load)

    def test_save_nonzero_raises_error(self):
        self.save_script('#!/bin/sh\nfalse')
        self.assert_raises_error(
            '.*exited with non-zero code: 1', self.plugin.save, self.all_data)

    def one_file_script(self, persisted):
        path = os.path.join(self.root, 'pem')
        self.save_script("""\
#!/bin/sh
case $1 in
  save) cat - > {path};;
  load) [ ! -f {path} ] ||  cat {path};;
  persisted) echo {persisted};;
esac
""".format(path=path, persisted=persisted))
        return path

    def test_it(self):
        path = self.one_file_script('cert chain csr account_key')
        # not yet persisted
        self.assertEqual(IOPlugin.EMPTY_DATA, self.plugin.load())
        # save some data
        self.plugin.save(self.all_data)
        self.assertTrue(os.path.exists(path))
        # loading should return the persisted data back in
        self.assertEqual(self.all_data, self.plugin.load())


@IOPlugin.register(path='chain.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class ChainFile(FileIOPlugin, OpenSSLIOPlugin):
    """Certificate chain plugin."""

    def persisted(self):
        return self.Data(account_key=False, csr=False, cert=False, chain=True)

    def load_from_content(self, output):
        chain = [self.load_cert(cert_data)
                 for cert_data in split_pems(output)]
        return self.Data(account_key=None, csr=None, cert=None, chain=chain)

    def save(self, data):
        return self.save_to_file(_PEMS_SEP.join(
            self.dump_cert(chain_cert) for chain_cert in data.chain))


class ChainFileTest(FileIOPluginTestMixin, UnitTestCase):
    """Tests for ChainFile."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = ChainFile


@IOPlugin.register(path='fullchain.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class FullChainFile(ChainFile):
    """Full chain file plugin."""

    def persisted(self):
        return self.Data(account_key=False, csr=False, cert=True, chain=True)

    def load(self):
        data = super(FullChainFile, self).load()
        if data.chain is None:
            cert, chain = None, None
        else:
            cert, chain = data.chain[0], data.chain[1:]
        return self.Data(account_key=data.account_key, csr=data.csr,
                         cert=cert, chain=chain)

    def save(self, data):
        return super(FullChainFile, self).save(self.Data(
            account_key=data.account_key, csr=data.csr,
            cert=None, chain=([data.cert] + data.chain)))


class FullChainFileTest(FileIOPluginTestMixin, UnitTestCase):
    """Tests for FullChainFile."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = FullChainFile


@IOPlugin.register(path='csr.der', typ=OpenSSL.crypto.FILETYPE_ASN1)
@IOPlugin.register(path='csr.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class CSRFile(FileIOPlugin, OpenSSLIOPlugin):
    """CSR file plugin."""

    def persisted(self):
        return self.Data(account_key=False, csr=True, cert=False, chain=False)

    def load_from_content(self, output):
        return self.Data(account_key=None, csr=self.load_csr(output),
                         cert=None, chain=None)

    def save(self, data):
        # TODO: CSRs should be read-only, it's silly to overwrite existing file
        return self.save_to_file(self.dump_csr(data.csr))


class CSRFileTest(FileIOPluginTestMixin, UnitTestCase):
    """Tests for CSRFile."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = CSRFile


@IOPlugin.register(path='cert.der', typ=OpenSSL.crypto.FILETYPE_ASN1)
@IOPlugin.register(path='cert.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class CertFile(FileIOPlugin, OpenSSLIOPlugin):
    """Certificate file plugin."""

    def persisted(self):
        return self.Data(account_key=False, csr=False, cert=True, chain=False)

    def load_from_content(self, output):
        return self.Data(account_key=None, csr=None,
                         cert=self.load_cert(output), chain=None)

    def save(self, data):
        return self.save_to_file(self.dump_cert(data.cert))


class CertFileTest(FileIOPluginTestMixin, UnitTestCase):
    """Tests for CertFile."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = CertFile


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
        '-h', '--help', action='store_true',
        help='Show this help message and exit.',
    )
    modes.add_argument(
        '--version', action='store_true',
        help='Display version and exit.'
    )
    modes.add_argument(
        '--revoke', action='store_true', default=False,
        help='Revoke existing certificate')
    modes.add_argument(
        '--test', action='store_true', default=False,
        help='Run tests and exit.',
    )
    modes.add_argument(
        '--integration_test', action='store_true', default=False,
        help='Run integration tests and exit.',
    )

    io_group = parser.add_argument_group('Certificate data files')
    io_group.add_argument(
        '-f', dest='ioplugins', action='append', default=[],
        metavar='PLUGIN', choices=sorted(IOPlugin.registered),
        help='Input/output plugin of choice, can be specified multiple '
        'times and, in fact, it should be specified as many times as it '
        'is necessary to cover all components: csr, certificate, chain. '
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

    parser.add_argument('root', nargs='?', help='Path to webroot.')
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


def save_validation(root, challb, validation):
    """Save validation to webroot.

    Args:
      root: Webroot path.
      challb: `acme.messages.ChallengeBody` with `http-01` challenge.
      validation: `http-01` validation
    """
    try:
        os.makedirs(root)
    except OSError as error:
        if error.errno != errno.EEXIST:
            # directory doesn't already exist and we cannot create it
            raise
    # TODO: this is a nasty hack
    path = os.path.join(root, challb.path.split('/')[-1])
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


class TestLoader(unittest.TestLoader):
    """simp_le test loader."""

    def load_tests_from_subclass(self, subcls):
        """Load tests which subclass from specific test case class."""
        module = __import__(__name__)
        return self.suiteClass([
            self.loadTestsFromTestCase(getattr(module, attr))
            for attr in dir(module)
            if isinstance(getattr(module, attr), type) and
            issubclass(getattr(module, attr), subcls)])


def test_suite(args, suite):
    """Run a specific test suite."""
    return EXIT_TESTS_OK if unittest.TextTestRunner(
        verbosity=(2 if args.verbose else 1)).run(
            suite).wasSuccessful() else EXIT_ERROR


def test(args):
    """Run tests (--test)."""
    return test_suite(args, unittest.TestSuite((
        TestLoader().load_tests_from_subclass(UnitTestCase),
        doctest.DocTestSuite(optionflags=(
            doctest.ELLIPSIS | doctest.IGNORE_EXCEPTION_DETAIL)),
    )))


def integration_test(args):
    """Run integration tests (--integration-test)."""
    return test_suite(
        args, unittest.defaultTestLoader.loadTestsFromTestCase(
            IntegrationTests))


def check_plugins_persist_all(ioplugins):
    """Do plugins cover all components (key/cert/chain)?"""
    persisted = IOPlugin.Data(
        account_key=False, csr=False, cert=False, chain=False)
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


def valid_existing_cert(cert, names, valid_min):
    """Is the existing cert data valid for enough time?

    If provided certificate is `None`, then always return True:

    >>> valid_existing_cert(cert=None, names=[], valid_min=0)
    False

    >>> cert = jose.ComparableX509(crypto_util.gen_ss_cert(
    ...     gen_pkey(1024), ['example.com'], validity=(60 *60)))

    Return True iff `valid_min` is not bigger than certificate lifespan:

    >>> valid_existing_cert(cert, ['example.com'], 0)
    True
    >>> valid_existing_cert(cert, ['example.com'], 60 * 60 + 1)
    False

    If SANs mismatch return False no matter if expiring or not:

    >>> valid_existing_cert(cert, ['example.net'], 0)
    False
    >>> valid_existing_cert(cert, ['example.org'], 60 * 60 + 1)
    False
    """
    if cert is None:
        return False  # no existing certificate
    else:  # renew existing?
        existing_sans = pyopenssl_cert_or_req_san(cert.wrapped)
        logger.debug('Existing SANs: %r, new: %r', existing_sans, names)
        return (set(existing_sans) == set(names) and
                not renewal_necessary(cert, valid_min))


def check_or_generate_account_key(args, existing):
    """Check or generate account key."""
    if existing is None:
        logger.info('Generating new account key')
        return jose.JWKRSA(key=rsa.generate_private_key(
            public_exponent=args.account_key_public_exponent,
            key_size=args.account_key_size,
            backend=default_backend(),
        ))
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
            logger.error(
                'Timed out while waiting for CA to verify '
                'challenge(s) for the following authorizations: %s',
                ', '.join(authzr.uri for _, authzr in error.exhausted)
            )

        invalid = [authzr for authzr in six.itervalues(error.updated)
                   if authzr.body.status == messages.STATUS_INVALID]
        if invalid:
            logger.error('CA marked some of the authorizations as invalid, '
                         'which likely means it could not access '
                         'http://example.com/.well-known/acme-challenge/X. '
                         'Did you set correct webroot path? Is there a '
                         'warning log entry about unsuccessful '
                         'self-verification? Are all your domains '
                         'accessible from the internet? Failing '
                         'authorizations: %s',
                         ', '.join(authzr.uri for authzr in invalid))

        raise Error('Challenge validation has failed, see error log.')
    return certr


def new_data(args, existing, names):
    """Issue and persist new key/cert/chain."""
    assert names
    client = registered_client(args, existing.account_key)

    authorizations = dict(
        (name, client.request_domain_challenges(
            name, new_authzr_uri=client.directory.new_authz))
        for name in names
    )
    if any(supported_challb(auth) is None
           for auth in six.itervalues(authorizations)):
        raise Error('CA did not offer http-01-only challenge combo. '
                    'This client is unable to solve any other challenges.')

    for name, auth in six.iteritems(authorizations):
        challb = supported_challb(auth)
        response, validation = challb.response_and_validation(client.key)
        save_validation(args.root, challb, validation)

        verified = response.simple_verify(
            challb.chall, name, client.key.public_key())
        if not verified:
            logger.warning('%s was not successfully self-verified. '
                           'CA is likely to fail as well!', name)
        else:
            logger.info('%s was successfully self-verified', name)

        client.answer_challenge(challb, response)

    certr = get_certr(client, existing.csr, authorizations)
    # pylint: disable=protected-access
    assert set(names) == set(crypto_util._pyopenssl_cert_or_req_san(
        certr.body.wrapped))  # pylint: disable=no-member
    persist_data(args, IOPlugin.Data(
        account_key=client.key, csr=existing.csr,
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
    # pylint: disable=too-many-return-statements
    """Run the script, throw exceptions on error."""
    parser = create_parser()
    try:
        args = parser.parse_args(cli_args)
    except SystemExit:
        return EXIT_ERROR

    if args.test:  # --test
        return test(args)
    elif args.integration_test:  # --integration_test
        return integration_test(args)
    elif args.help:  # --help
        parser.print_help()
        return EXIT_HELP_VERSION_OK
    elif args.version:  # --version
        sys.stdout.write('%s %s\n' % (os.path.basename(sys.argv[0]), VERSION))
        return EXIT_HELP_VERSION_OK

    setup_logging(args.verbose)
    logger.debug('%r parsed as %r', cli_args, args)

    if args.revoke:  # --revoke
        return revoke(args)

    if args.root is None:
        raise Error('Webroot argument is required')

    check_plugins_persist_all(args.ioplugins)

    existing_data = load_existing_data(args.ioplugins)
    assert existing_data.csr is not None
    # pylint: disable=protected-access
    names = crypto_util._pyopenssl_cert_or_req_san(
        existing_data.csr.wrapped)
    if valid_existing_cert(existing_data.cert, names, args.valid_min):
        logger.info('Certificates already exist and renewal is not '
                    'necessary, exiting with status code %d.', EXIT_NO_RENEWAL)
        return EXIT_NO_RENEWAL
    else:
        new_data(args, existing_data, names)
        return EXIT_RENEWAL


def exit_with_error(message):
    """Print `message` and debugging tips to STDERR, exit with EXIT_ERROR."""
    sys.stderr.write('%s\n\nDebugging tips: -v improves output verbosity. '
                     'Help is available under --help.\n' % message)
    return EXIT_ERROR


def main(cli_args=sys.argv[1:]):
    """Run the script, with exceptions caught and printed to STDERR."""
    # logging (handler) is not set up yet, use STDERR only!
    try:
        return main_with_exceptions(cli_args)
    except Error as error:
        return exit_with_error(error)
    except messages.Error as error:
        return exit_with_error('ACME server returned an error: %s\n' % error)
    except BaseException as error:  # pylint: disable=broad-except
        # maintain manifest invariant: `exit 1` iff renewal not
        # necessary, `exit 2` iff error
        traceback.print_exc(file=sys.stderr)
        return exit_with_error(
            '\nUnhandled error has happened, traceback is above')


class MainTest(UnitTestCase):
    """Unit tests for main()."""

    # this is a test suite | pylint: disable=missing-docstring

    @classmethod
    def _run(cls, args):
        return main(shlex.split(args))

    @mock.patch('sys.stdout')
    def test_exit_code_help_version_ok(self, dummy_stdout):
        self.assertEqual(EXIT_HELP_VERSION_OK, self._run('--help'))
        self.assertEqual(EXIT_HELP_VERSION_OK, self._run('--version'))

    @mock.patch('sys.stderr')
    def test_error_exit_codes(self, dummy_stderr):
        test_args = [
            '',  # no args - no good
            '--bar',  # unrecognized
            '-f account_key.json -f csr.pem -f fullchain.pem',  # no root
        ]
        # missing plugin coverage
        test_args.extend([
            '-f account_key.json',
            '-f csr.pem',
            '-f account_key.json -f csr.pem',
            '-f csr.pem -f cert.pem',
            '-f csr.pem -f chain.pem',
            '-f fullchain.pem',
            '-f cert.pem -f fullchain.pem',
        ])

        for args in test_args:
            self.assertEqual(
                EXIT_ERROR, self._run(args), 'Wrong exit code for %s' % args)


@contextlib.contextmanager
def chdir(path):
    """Context manager that adjusts CWD."""
    old_path = os.getcwd()
    os.chdir(path)
    try:
        yield old_path
    finally:
        os.chdir(old_path)


class IntegrationTests(unittest.TestCase):
    """Integrations tests with Boulder.

    Prerequisites:
    - /etc/hosts:127.0.0.1 le.wtf
    - Boulder running on localhost:4000
    - Boulder verifying http-01 on port 5002
    """
    # this is a test suite | pylint: disable=missing-docstring

    SERVER = 'http://localhost:4000/directory'
    BOULDER_MIN_BITS = 2048
    TOS_SHA256 = ('b16e15764b8bc06c5c3f9f19bc8b99fa'
                  '48e7894aa5a6ccdad65da49bbf564793')
    PORT = 5002

    @classmethod
    def _run(cls, args):
        logger.debug('Running main with the following args: %s', args)
        return main(shlex.split(args))

    @classmethod
    @contextlib.contextmanager
    def _new_swd(cls):
        path = tempfile.mkdtemp()
        try:
            with chdir(path) as old_path:
                yield old_path, path
        finally:
            shutil.rmtree(path)

    @classmethod
    def get_stats(cls, *paths):
        def _single_path_stats(path):
            all_stats = os.stat(path)
            stats = dict(
                (name[3:], getattr(all_stats, name)) for name in dir(all_stats)
                # skip access (read) time, includes _ns.
                if name.startswith('st_') and not name.startswith('st_atime'))
            # st_*time has a second-granularity so it can't be
            # reliably used to prove that contents have changed or not
            with open(path, 'rb') as f:  # pylint: disable=invalid-name
                stats.update(checksum=hashlib.sha256(f.read()).hexdigest())
            return stats
        return dict((path, _single_path_stats(path)) for path in paths)

    def test_it(self):
        webroot = os.path.join(
            os.getcwd(), 'public_html', '.well-known', 'acme-challenge')
        args = ('--server %s --tos_sha256 %s -f account_key.json '
                '-f csr.pem -f fullchain.pem %s' % (
                    self.SERVER, self.TOS_SHA256, webroot))
        files = ('account_key.json', 'csr.pem', 'fullchain.pem')

        with self._new_swd():
            IOPlugin.registered['csr.pem'].save(IOPlugin.EMPTY_DATA._replace(
                csr=jose.ComparableX509(
                    gen_csr(gen_pkey(self.BOULDER_MIN_BITS), [b'le.wtf']))))

            self.assertEqual(EXIT_RENEWAL, self._run(args))
            initial_stats = self.get_stats(*files)

            self.assertEqual(EXIT_NO_RENEWAL, self._run(args))
            # No renewal => no files should be touched
            # NB get_stats() would fail if file didn't exist
            self.assertEqual(initial_stats, self.get_stats(*files))

            self.assertEqual(EXIT_REVOKE_OK, self._run(
                '--server %s --revoke -f account_key.json -f fullchain.pem' %
                self.SERVER))
            # Revocation shouldn't touch any files
            self.assertEqual(initial_stats, self.get_stats(*files))

            # Changing SANs should trigger "renewal"
            self.assertEqual(
                EXIT_RENEWAL, self._run('%s %s' % (args, webroot)))


if __name__ == '__main__':
    raise SystemExit(main())
