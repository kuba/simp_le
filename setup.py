import codecs
import os
import sys
import setuptools


here = os.path.abspath(os.path.dirname(__file__))
readme = codecs.open(os.path.join(here, 'README.rst'), encoding='utf-8').read()
version = '0'  # set static for now

install_requires = [
    'acme>=0.3,<0.5',
    'cryptography',
    'pyOpenSSL',
    'pytz',
    'requests',
]

if sys.version_info < (2, 7):
    install_requires.extend([
        'argparse',
        'mock<1.1.0',
    ])
else:
    install_requires.extend([
        'mock',
    ])

tests_require = [
    'pep8',
    'pylint',
]

setuptools.setup(
    name='simp_le',
    version=version,
    author='Jakub Warmuz',
    author_email='jakub@warmuz.org',
    description="Simple Let's Encrypt Client",
    long_description=readme,
    license='GPLv3',
    url='https://github.com/kuba/simp_le',
    py_modules=['simp_le'],
    install_requires=install_requires,
    extras_require={
        'tests': tests_require,
    },
    entry_points={
        'console_scripts': [
            'simp_le = simp_le:main',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],
)
