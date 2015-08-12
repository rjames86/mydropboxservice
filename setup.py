#!/usr/bin/env python

from setuptools import setup

requires = ['dropbox']

setup(
    name="sharelink",
    version="0.1",
    author='Ryan M',
    author_email='ryan@ryanmo.co',
    description="Small library for sharing files with Dropbox",
    packages=['mydropbox'],
    scripts=['bin/sharelink'],
    install_requires=requires,
)
