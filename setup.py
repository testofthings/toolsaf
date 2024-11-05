"""Setup"""

from setuptools import setup, find_packages

with open('requirements.txt', encoding="utf-8") as f:
    requirements = f.read().splitlines()

setup(
    name='tdsaf',
    version='0.0',
    packages=[
        'tdsaf',
        'tdsaf.adapters',
        'tdsaf.common',
        'tdsaf.core',
    ],
    author="Rauli Kaksonen",
    author_email="rauli.kaksonen@testofthings.com",
    entry_points={
        'console_scripts': [
            'tdsaf=tdsaf.client_tool:main',
        ],
    },
    description='TDSA Framework',
    long_description='Tool-Driven Security Assessment Framework',
    url='https://github.com/testofthings/tdsaf',
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.10',
)
