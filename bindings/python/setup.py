"""Setup script for ciris-verify Python bindings."""

from setuptools import setup, find_packages
from pathlib import Path

here = Path(__file__).parent
readme = (here / "README.md").read_text() if (here / "README.md").exists() else ""

setup(
    name="ciris-verify",
    version="0.1.0",
    description="Python bindings for CIRISVerify hardware-rooted license verification",
    long_description=readme,
    long_description_content_type="text/markdown",
    author="CIRIS Engineering",
    author_email="engineering@ciris.ai",
    url="https://github.com/CIRISAI/CIRISVerify",
    license="Proprietary",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "pydantic>=2.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "mypy>=1.0.0",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Typing :: Typed",
    ],
    package_data={
        "ciris_verify": ["py.typed"],
    },
)
