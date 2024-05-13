import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="netco-unifi-api-client",
    version="1.0.9.1",
    author="Ramjad Ramautar",
    author_email="ramjad@netco.nl",
    description="A client for UniFi Network Controller API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.mgmt.netco.nl/ubnt/unifi_api_client",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries",
        "Topic :: System :: Networking",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
