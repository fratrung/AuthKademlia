#!/usr/bin/env python
from setuptools import setup, find_packages
import kademlia

setup(
    name="kademlia",
    version=kademlia.__version__,
    description="Kademlia is a distributed hash table for decentralized peer-to-peer computer networks.",
    long_description=open("README.md", encoding='utf-8').read(),
    long_description_content_type='text/markdown',
    author="Francesco Trungadi",
    author_email="francesco.trung@gmail.com",
    license="MIT",
    url="https://github.com/fratrung/AuthKademlia",
    packages=find_packages(),
    install_requires=open("requirements.txt").readlines(),
    dependency_links=[
        "git+https://github.com/GiacomoPope/dilithium-py.git",
        "git+https://github.com/GiacomoPope/kyber-py.git",
    ],
    classifiers=[
      "Development Status :: 5 - Production/Stable",
      "Intended Audience :: Developers",
      "License :: OSI Approved :: MIT License",
      "Operating System :: OS Independent",
      "Programming Language :: Python",
      "Programming Language :: Python :: 3",
      "Programming Language :: Python :: 3.5",
      "Programming Language :: Python :: 3.6",
      "Programming Language :: Python :: 3.7",
      "Topic :: Software Development :: Libraries :: Python Modules",
    ]
)
