# Installation

You can install in-toto using either pip, or your favorite package manager.

```{note}

We strongly suggest you use a [virtual environment](https://virtualenv.pypa.io/en/stable/) if you are installing in_toto
with pip or from source.
```

## On Debian

You can install in-toto on Debian using apt/apt-get:

> ```sh
> apt install in-toto
> ```

This should provide all the dependencies you need to run in-toto.

## On Arch Linux

On Arch Linux, you can install in-toto by using pacman:

> ```sh
> pacman -S in-toto
> ```

## Using PIP

To install using pip, simply run:

> ```sh
> pip install in-toto
> ```

You may also need to install some system dependencies (depending on your host).
These are:

- [OpenSSL](https://openssl.org) used to generate and verify RSA signatures,
  and to export and verify signatures created with GPG.
- [GPG](https://gnupg.org) if you plan on generating PGP signatures
  (verification works without GPG).

## Installing from Source

If your system doesn't provide in-toto, you can install it from the source. To
do so, you will need the following dependencies:

- [OpenSSL](https://openssl.org)
- [python-cryptography](https://cryptography.readthedocs.io)
- [python-securesystemslib](https://github.com/secure-systems-lab/securesystemslib/)
- [pip](https://pypi.org/project/pip/) version `19.0` or higher

With these dependencies installed, fetch the latest tarball of in-toto
[here](https://github.com/in-toto/in-toto/releases). Unpack it on a directory
you trust and execute the following commands on a terminal:

> ```sh
> pip install .
> ```

## Installing for Development

To install in-toto in editable mode, together with development dependencies,
clone the [in-toto git repository](https://github.com/in-toto/in-toto),
change into the project root directory, and install with pip:

> ```sh
> pip install -r requirements-dev.txt
> ```
