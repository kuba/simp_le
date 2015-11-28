import sys
import setuptools


install_requires = [
    'acme==0.0.0.dev20151123',
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
    author='Jakub Warmuz',
    author_email='jakub@warmuz.org',
    license='GPLv3',

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
)
