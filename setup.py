#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.rst", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="autorop",
    version="0.0.0",
    author="Mariusz Skoneczko",
    author_email="mariusz@skoneczko.com",
    description="CTF pwn challenge automation framework",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/mariuszskon/autorop",
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    packages=find_packages(),
    entry_points={"console_scripts": ["autorop=autorop.cli:main"]},
    install_requires=[
        "pwntools",
    ],
)
