from setuptools import setup, find_packages

setup(
    name="jwt-audit-sentinel",
    version="0.1.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "jwt-audit-sentinel=jwt_audit_sentinel.cli:main",
            "jwt-audit=jwt_audit_sentinel.cli:main",
        ],
    },
)
