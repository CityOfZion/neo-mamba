"""The setup script."""
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop
from contextlib import suppress
from pkg_resources import parse_version
import sys


class InstallCommand(install):
    user_options = install.user_options + [
        ('without-leveldb', None, 'Do not install leveldb requirements'),
    ]

    def initialize_options(self):
        super().initialize_options()
        # Initialize options
        self.without_leveldb = None

    def run(self):        # Use options
        if self.without_leveldb:
            print("install command called!")
            with suppress(ValueError):
                idx = list(map(lambda i: "plyvel" in i, self.distribution.install_requires)).index(True)
                self.distribution.install_requires.pop(idx)

        super().run()


class DevelopCommand(develop):
    user_options = develop.user_options + [
        ('without-leveldb', None, 'Do not install leveldb requirements'),
    ]

    def initialize_options(self):
        super().initialize_options()
        # Initialize options
        self.without_leveldb = None

    def run(self):
        # Use options
        if self.without_leveldb:
            with suppress(ValueError):
                idx = list(map(lambda i: "plyvel" in i, self.distribution.install_requires)).index(True)
                self.distribution.install_requires.pop(idx)

        super().run()

try:
    from pip._internal.req import parse_requirements
    from pip import __version__ as __pip_version
    pip_version = parse_version(__pip_version)
    if (pip_version >= parse_version("20")):
        from pip._internal.network.session import PipSession
    elif (pip_version >= parse_version("10")):
        from pip._internal.download import PipSession
except ImportError:  # pip version < 10.0
    from pip.req import parse_requirements
    from pip.download import PipSession

with open('README.rst') as readme_file:
    readme = readme_file.read()


leveldb_requirements = ["plyvel==1.3.0" if sys.platform in ["darwin", "linux"] else "plyvel-win32"]

# get the requirements from requirements.txt
install_reqs = parse_requirements('requirements.txt', session=PipSession())
reqs = []
for ir in install_reqs:
    if hasattr(ir, 'requirement'):
        reqs.append(str(ir.requirement))
    else:
        reqs.append(str(ir.req))
setup(
    name='neo-mamba',
    python_requires='==3.8.*',
    version='0.8',
    description="Python SDK for the NEO 3 blockchain",
    long_description=readme,
    long_description_content_type="text/x-rst",
    author="Erik van den Brink",
    author_email='erik@coz.io',
    maintainer="Erik van den Brink",
    maintainer_email='erik@coz.io',
    url='https://github.com/CityOfZion/neo-mamba',
    packages=find_packages(include=['neo3']),
    include_package_data=True,
    install_requires=reqs,
    extras_require={"leveldb": leveldb_requirements},
    license="MIT license",
    zip_safe=False,
    keywords='neo3, python, SDK',
    entry_points={
        'sphinx.html_themes': [
            'neo3 = docs.source._theme',
        ]
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.8',
    ],
    cmdclass={
        'install': InstallCommand,
        'develop': DevelopCommand
    }
)
