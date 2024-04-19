"""Setup"""

from setuptools import setup, find_packages

with open('requirements.txt', encoding="utf-8") as f:
    requirements = f.read().splitlines()

setup(
    name='tcsfw',
    version='0.0',
    packages=['tcsfw'],
    author="Rauli Kaksonen",
    author_email="rauli.kaksonen@gmail.com",
    description='Tcsfw',
    long_description='Trasparent cyber security framework',
    url='https://github.com/ouspg/tcsfw',
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.10',
)
