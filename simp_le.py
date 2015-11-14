#!/usr/bin/env python
#
# Simple Let's Encrypt client.
#
# Copyright (C) 2016  Jakub Warmuz
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
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

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
from acme import jose
from acme import messages


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

VERSION = '0'
URL = 'https://github.com/kuba/simp_le'

LE_STAGING_URI = 'https://acme-staging.api.letsencrypt.org/directory'
# https://letsencrypt.org/2015/11/09/why-90-days.html
LE_CERT_VALIDITY = 90 * 24 * 60 * 60
DEFAULT_VALID_MIN = LE_CERT_VALIDITY / 3


class Error(Exception):
    """simp_le error."""


class TestCase(unittest.TestCase):
    """simp_le unit test case."""


def gen_pkey(bits):
    """Generate a private key.

    >>> gen_pkey(1024)  # doctest: +ELLIPSIS
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
    ...     gen_csr(gen_pkey(1024), [b'example.com', b'example2.com']))
    ['example.com', 'example2.com']

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


def load_cert(*args, **kwargs):
    """Load X509 certificate."""
    return jose.ComparableX509(OpenSSL.crypto.load_certificate(
        *args, **kwargs))


class AccountKey(object):
    """Acount key loading/saving."""
    PATH = 'account_key.json'

    @classmethod
    def load(cls):
        logger.debug('Loading account key from %s', cls.PATH)
        with open(cls.PATH) as account_key_file:
            return jose.JWKRSA.json_loads(account_key_file.read())

    @classmethod
    def save(cls, jwk):
        logger.debug('Saving account key at %s', cls.PATH)
        with open(cls.PATH, 'w') as account_key_file:
            account_key_file.write(jwk.json_dumps())

    @classmethod
    def get(cls, args):
        try:
            account_key = cls.load()
        except IOError as error:
            logger.debug(error)
            if error.errno != errno.ENOENT:
                raise
            logger.info('Creating new account key')
            account_key = jose.JWKRSA(key=rsa.generate_private_key(
                public_exponent=args.account_key_public_exponent,
                key_size=args.account_key_size,
                backend=default_backend()
            ))
            cls.save(account_key)
        else:
            assert account_key.key.key_size == args.account_key_size
            assert (account_key.public_key().key.public_numbers().e ==
                    args.account_key_public_exponent)
        return account_key


class AccountKeyTest(TestCase):
    """Tests for AccountKey."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.path = os.path.join(self.root, AccountKey.PATH)
        self.args = mock.Mock(
            account_key_public_exponent=65537, account_key_size=1024)

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_it(self):
        with mock.patch.object(AccountKey, 'PATH', new=self.path):
            self.assertRaises(IOError, AccountKey.load)
            account_key = AccountKey.get(self.args)
            self.assertTrue(os.path.exists(AccountKey.PATH))
            account_key2 = AccountKey.get(self.args)
            account_key3 = AccountKey.load()
            self.assertEqual(account_key, account_key2)
            self.assertEqual(account_key, account_key3)


class Vhost(collections.namedtuple('Vhost', 'name root')):
    """Vhost: domain name and public html root."""
    _SEPRATOR = ':'

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
        parts = data.split(cls._SEPRATOR, 1)
        parts.append(None)
        return cls(name=parts[0], root=parts[1])


class IOPlugin(object):
    """Input/output plugin."""
    __metaclass__ = abc.ABCMeta

    Data = collections.namedtuple('IOPluginData', 'key cert chain')
    EMPTY_DATA = Data(key=None, cert=None, chain=None)

    def __init__(self, path, **dummy_kwargs):
        self.path = path

    @abc.abstractmethod
    def persisted(self):
        """Which data is persisted by this plugin?"""
        raise NotImplementedError()

    @abc.abstractmethod
    def load(self):
        """Load persisted data.

        Returns:
          IOPlugin.Data
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def save(self, data):
        """Save data to file system.

        Args:
          data: IOPlugin.Data
        """
        raise NotImplementedError()

    # Plugin registration magic
    registered = {}

    @classmethod
    def register(cls, **kwargs):
        def _reg(plugin_cls):
            plugin = plugin_cls(**kwargs)
            assert (os.path.sep not in plugin.path and
                    plugin.path not in ('.', '..'))
            cls.registered[plugin.path] = plugin
            return plugin_cls
        return _reg


class OpenSSLIOPlugin(IOPlugin):  # pylint: disable=abstract-method

    def __init__(self, typ=OpenSSL.crypto.FILETYPE_PEM, **kwargs):
        self.typ = typ
        super(OpenSSLIOPlugin, self).__init__(**kwargs)

    def load_key(self, data):
        return OpenSSL.crypto.load_privatekey(self.typ, data)

    def dump_key(self, data):
        return OpenSSL.crypto.dump_privatekey(self.typ, data).strip()

    def load_cert(self, data):
        return load_cert(self.typ, data)

    def dump_cert(self, data):
        # pylint: disable=protected-access
        return OpenSSL.crypto.dump_certificate(self.typ, data._wrapped).strip()


@IOPlugin.register(path='external_pem.sh', typ=OpenSSL.crypto.FILETYPE_PEM)
class ExternalIOPlugin(OpenSSLIOPlugin):
    """External IO Plugin."""

    _SEP = b'\n\n'

    @property
    def _popen_path(self):
        return './' + self.path

    def persisted(self):
        try:
            output = subprocess.check_output([self._popen_path, 'persisted'])
        except OSError as error:
            if error.errno != errno.EEXIST:
                return self.EMPTY_DATA
            raise
        return self.Data(
            key=('key' in output),
            cert=('cert' in output),
            chain=('chain' in output),
        )

    def load(self):
        try:
            output = subprocess.check_output(
                [self._popen_path, 'load']).split(self._SEP)
        except subprocess.CalledProcessError as error:
            logger.debug(error)
            return self.EMPTY_DATA
        # Do NOT log `output` as it contains key material
        persisted = self.persisted()
        key = self.load_key(output.pop(0)) if persisted.key else None
        cert = self.load_cert(output.pop(0)) if persisted.cert else None
        chain = ([self.load_cert(cert_data) for cert_data in output]
                 if persisted.chain else None)
        return self.Data(key=key, cert=cert, chain=chain)

    def save(self, data):
        persisted = self.persisted()
        output = []
        if persisted.key:
            output.append(self.dump_key(data.key))
        if persisted.cert:
            output.append(self.dump_cert(data.cert))
        if persisted.chain:
            output.extend(self.dump_cert(cert_data)
                          for cert_data in data.chain)
        logger.info('Calling `%s save` and piping data through',
                    self._popen_path)
        proc = subprocess.Popen(
            [self._popen_path, 'save'], stdin=subprocess.PIPE)
        stdout, stderr = proc.communicate(input=self._SEP.join(output))
        logger.debug(stdout)
        logger.error(stderr)


@IOPlugin.register(path='chain.der', typ=OpenSSL.crypto.FILETYPE_ASN1)
@IOPlugin.register(path='chain.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class ChainFile(OpenSSLIOPlugin):
    """Certificate chain plugin."""

    _SEP = '\n\n'  # TODO: do all webservers like this?

    def persisted(self):
        return self.Data(key=False, cert=False, chain=True)

    def load(self):
        with open(self.path, 'rb') as chain_file:
            output = chain_file.read().split(self._SEP)
        chain = [self.load_cert(cert_data) for cert_data in output]
        return self.Data(key=None, cert=None, chain=chain)

    def save(self, data):
        logger.info('Saving %s', self.path)
        output = (self.dump_cert(chain_cert) for chain_cert in data.chain)
        with open(self.path, 'wb') as chain_file:
            chain_file.write(self._SEP.join(output))


@IOPlugin.register(path='fullchain.der', typ=OpenSSL.crypto.FILETYPE_ASN1)
@IOPlugin.register(path='fullchain.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class FullChainFile(ChainFile):
    """Full chain file plugin."""

    def persisted(self):
        return self.Data(key=False, cert=True, chain=True)

    def load(self):
        output = super(FullChainFile, self).load()
        return self.Data(
            key=output.key, cert=output.chain[0], chain=output.chain[1:])

    def save(self, data):
        # no need to log here, parent already does it
        return super(FullChainFile, self).save(self.Data(
            key=data.key, cert=None, chain=([data.cert] + data.chain)))


@IOPlugin.register(path='key.der', typ=OpenSSL.crypto.FILETYPE_ASN1)
@IOPlugin.register(path='key.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class KeyFile(OpenSSLIOPlugin):
    """Private key file plugin."""

    def persisted(self):
        return self.Data(key=True, cert=False, chain=False)

    def load(self):
        with open(self.path, 'rb') as key_file:
            key = self.load_key(key_file.read())
        return self.Data(key=key, cert=None, chain=None)

    def save(self, data):
        logger.info('Saving %s', self.path)
        output = self.dump_key(data.key)
        with open(self.path, 'wb') as key_file:
            key_file.write(output)


@IOPlugin.register(path='cert.der', typ=OpenSSL.crypto.FILETYPE_ASN1)
@IOPlugin.register(path='cert.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class CertFile(OpenSSLIOPlugin):
    """Certificate file plugin."""

    def persisted(self):
        return self.Data(key=False, cert=True, chain=False)

    def load(self):
        with open(self.path, 'rb') as cert_file:
            output = cert_file.read()
        return self.Data(key=None, cert=self.load_cert(output), chain=None)

    def save(self, data):
        output = self.dump_cert(data.cert)
        with open(self.path, 'wb') as cert_file:
            cert_file.write(output)


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
        '-d', dest='vhosts', action='append',
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
        help="Minimum validity of the resulting certificate.",
    )

    reg = parser.add_argument_group(
        'Registration', description='This client will automatically '
        'register an account with the ACME CA specified by `--server.` '
        'Secret account key can be found in %s' % AccountKey.PATH,
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
        '--server', metavar='URI', default=LE_STAGING_URI,
        help='Directory URI for the CA ACME API endpoint.',
    )

    return parser


def supported_challb(authorization):
    for combo in authorization.body.combinations:
        first_challb = authorization.body.challenges[combo[0]]
        if len(combo) == 1 and isinstance(
                first_challb.chall, challenges.HTTP01):
            return first_challb
    return None


def _compute_roots(vhosts, default_root):
    roots = {}
    for vhost in vhosts:
        if vhost.root is not None:
            root = vhost.root
        else:
            root = default_root
        roots[vhost.name] = root

    empty_roots = dict((name, root)
                       for name, root in roots.iteritems() if root is None)
    if empty_roots:
        raise ValueError(empty_roots)
    return roots


def save_validation(root, challb, validation):
    try:
        os.makedirs(os.path.join(root, challb.URI_ROOT_PATH))
    except OSError as error:
        if not error.errno == errno.EEXIST:
            raise
    path = os.path.join(root, challb.path[1:])
    with open(path, 'w') as validation_file:
        validation_file.write(validation.encode())


def sha256_of_uri_contents(uri, chunk_size=10):
    """Get SHA256 of URI contents.

    >>> with mock.patch('requests.get') as mock_get:
    ...     sha256_of_uri_contents('https://example.com')
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    """
    h = hashlib.sha256()
    response = requests.get(uri, stream=True)
    for chunk in response.iter_content(chunk_size):
        h.update(chunk)
    return h.hexdigest()


def componentwise_or(a, b):
    """Compoentwise OR.

    >>> componentwise_or((False, False), (False, False))
    (False, False)
    >>> componentwise_or((True, False), (False, False))
    (True, False)
    >>> componentwise_or((True, False), (False, True))
    (True, True)
    """
    return tuple(x or y for x, y in zip(a, b))


def persist_data(args, cert, chain, key):
    for plugin_name in args.ioplugins:
        IOPlugin.registered[plugin_name].save(
            IOPlugin.Data(key=key, cert=cert, chain=chain))


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
    dt = datetime.datetime.strptime(timestamp[:12], '%Y%m%d%H%M%S')
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
        doctest.DocTestSuite(),
        unittest.defaultTestLoader.loadTestsFromName(__name__)
    ))
    raise SystemExit(not unittest.TextTestRunner(
        verbosity=(2 if args.verbose else 1)).run(
            suite).wasSuccessful())


def _persisted_plugins_cover_all_compoenents(ioplugins):
    persisted = IOPlugin.Data(key=False, cert=False, chain=False)
    for plugin_name in ioplugins:
        persisted = IOPlugin.Data(*componentwise_or(
            persisted, IOPlugin.registered[plugin_name].persisted()))
    return persisted == IOPlugin.Data(key=True, cert=True, chain=True)


def _load_existing_data(ioplugins):
    components = tuple(IOPlugin.EMPTY_DATA._asdict())
    existing = IOPlugin.EMPTY_DATA
    for plugin_name in ioplugins:
        try:
            data = IOPlugin.registered[plugin_name].load()
        except IOError as error:
            if not error.errno != errno.EEXIST:
                raise
        else:
            for component in components:
                existing_data = getattr(existing, component)
                if existing_data is None:
                    new_data = existing._asdict()
                    new_data[component] = getattr(data, component)
                    existing = IOPlugin.Data(**new_data)
                elif getattr(data, component) is not None:
                    assert existing_data == getattr(data, component)

    # All or nothing!
    assert existing == IOPlugin.EMPTY_DATA or all(
        getattr(existing, component) is not None for component in components)
    return existing


def _valid_existing_data(ioplugins, vhosts, valid_min):
    existing = _load_existing_data(ioplugins)

    if existing != IOPlugin.EMPTY_DATA:
        # pylint: disable=protected-access
        existing_sans = crypto_util._pyopenssl_cert_or_req_san(existing.cert)
        logger.debug('Existing SANs: %r', existing_sans)

        assert set(existing_sans) == set(vhost.name for vhost in vhosts)

        # Renew?
        if not renewal_necessary(existing.cert, valid_min):
            return True
        else:
            return False


def _registered_client(args):
    """Create ACME client, register if necessary."""
    key = AccountKey.get(args)
    net = acme_client.ClientNetwork(key, user_agent=args.user_agent)
    client = acme_client.Client(directory=args.server, key=key, net=net)
    try:
        regr = client.register()
    except messages.Error as error:
        if error.detail != 'Registration key is already in use':
            raise
    else:
        if regr.terms_of_service is not None:
            tos_hash = sha256_of_uri_contents(regr.terms_of_service)
            logger.debug('TOS hash: %s', tos_hash)
            if args.tos_sha256 != tos_hash:
                raise Error('TOS hash mismatch. Found: %s.' % tos_hash)
            client.update_registration(regr.update(
                body=regr.body.update(agreement=regr.terms_of_service)))

    return client


def _new_data(args):
    """Issue and persist new key/cert/chain."""
    roots = _compute_roots(args.vhosts, args.default_root)
    logger.debug('Computed roots: %r', roots)

    client = _registered_client(args)

    authorizations = dict(
        (vhost.name, client.request_domain_challenges(
            vhost.name, new_authz_uri=client.directory.new_authz))
        for vhost in args.vhosts
    )
    assert all(supported_challb(auth) is not None
               for auth in authorizations.itervalues())

    for name, auth in authorizations.iteritems():
        challb = supported_challb(auth)
        response, validation = challb.response_and_validation(client.key)
        save_validation(roots[name], challb, validation)

        verified = response.simple_verify(
            challb.chall, name, client.key.public_key())
        if not verified:
            logger.warning('%s was not succesfully verified by the '
                           'client. CA is likely to fail as well!', name)
        else:
            logger.info('%s was succesfully verified by the client')

        client.answer_challenge(challb, response)

    key = gen_pkey(args.cert_key_size)
    csr = gen_csr(key, roots)
    certr, _ = client.poll_and_request_issuance(csr, authorizations.values())
    chain = client.fetch_chain(certr)
    persist_data(args, certr.body, chain, key)


def _setup_logging(verbose):
        # set up basic logging
    level = logging.DEBUG if verbose else logging.INFO
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    handler = logging.StreamHandler()
    handler.setLevel(level)
    formatter = logging.Formatter(
        fmt='%(asctime)s:%(levelname)s:%(name)s: %(message)s',
    )
    formatter.converter = time.gmtime  # UTC instead of localtime
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)


def _main(cli_args):
    args = create_parser().parse_args(cli_args)
    if args.test:  # --test
        test(args)
    elif args.vhosts is None:
        raise Error('You must set at least one -d/--vhost')

    _setup_logging(args.verbose)
    logger.debug('%r parsed as %r', cli_args, args)

    if not _persisted_plugins_cover_all_compoenents(args.ioplugins):
        raise Error("Selected IO plugins do not cover all components.")

    if _valid_existing_data(args.ioplugins, args.vhosts, args.valid_min):
        logger.info('Certificates already exist and renewal is not '
                    'necessary, exiting.')
    else:
        _new_data(args)


def main(cli_args=sys.argv[1:]):
    try:
        _main(cli_args)
    except Error as error:
        logger.error(error)
        sys.exit(1)


if __name__ == '__main__':
    main()
