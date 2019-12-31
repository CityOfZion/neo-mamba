"""The setup script."""
from setuptools import setup, find_packages

try:  # pip version >= 10.0
    from pip._internal.req import parse_requirements
    from pip._internal.download import PipSession
except ImportError:  # pip version < 10.0
    from pip.req import parse_requirements
    from pip.download import PipSession

with open('README.rst') as readme_file:
    readme = readme_file.read()

# get the requirements from requirements.txt
install_reqs = parse_requirements('requirements.txt', session=PipSession())
reqs = [str(ir.req) for ir in install_reqs]

setup(
    name='neo3-python',
    python_requires='>=3.7',
    version='0.0.1',
    description="Python SDK for the NEO 3 blockchain",
    long_description=readme,
    author="Erik van den Brink",
    author_email='erik@coz.io',
    maintainer="Erik van den Brink",
    maintainer_email='erik@coz.io',
    url='https://github.com/CityOfZion/neo3-python',
    packages=find_packages(include=['neo3']),
    include_package_data=True,
    install_requires=reqs,
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
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
    ]
)
