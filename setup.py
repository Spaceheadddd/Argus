from setuptools import setup, find_packages

setup(
    name="argus-scanner",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "rich>=13.7.0",
        "beautifulsoup4>=4.12.0",
    ],
    entry_points={
        "console_scripts": [
            # To rename: change "argus" to your new tool name here
            # and update TOOL_NAME in scanner/core/branding.py
            "argus=main:cli",
        ],
    },
    python_requires=">=3.9",
)
