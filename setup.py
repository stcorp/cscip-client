from setuptools import setup

setup(
    name="cscip-client",
    version="1.0",
    description="CSC Interface delivery Point client",
    url="https://github.com/stcorp/cscip-client",
    author="S[&]T",
    license="BSD",
    py_modules=["cscip_client"],
    entry_points={"console_scripts": ["cscip-client = cscip_client:main"]},
    install_requires=["oauthlib", "requests", "requests-oauthlib"]
)
