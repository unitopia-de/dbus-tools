from setuptools import setup, find_packages
import sys, os

version = '0.0'

setup(name='MUDFTPD',
      version=version,
      description="FTPD for MUDs",
      long_description="""\
""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='',
      author='Alexander Motzkau',
      author_email='gnomi@unitopia.de',
      url='',
      license='BSD',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=True,
      install_requires=[
          # -*- Extra requirements: -*-
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
