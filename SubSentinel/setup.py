from setuptools import setup, find_packages

setup(
    name="subsentinel",
    version="2.0.0",
    description="Professional Subdomain Takeover Detection Framework",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Security Research",
    python_requires=">=3.9",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "fingerprints": ["*.yaml"],
    },
    install_requires=[
        "aiohttp>=3.9.0",
        "httpx>=0.27.0",
        "dnspython>=2.6.0",
        "playwright>=1.44.0",
        "rich>=13.7.0",
        "PyYAML>=6.0.1",
        "aiosqlite>=0.20.0",
        "aiosmtplib>=3.0.0",
        "certifi>=2024.2.2",
    ],
    entry_points={
        "console_scripts": [
            "subsentinel=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
