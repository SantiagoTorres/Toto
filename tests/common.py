#!/usr/bin/env python

# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  common.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  Feb 6, 2018

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Common code for in-toto unittests, import like so:
  `import tests.common`

  Tests importing this module, should be run from the project root, e.g.:
  `python tests/test_in_toto_run.py`
  or using the aggregator script (preferred way):
  `python tests/runtests.py`.

"""
import inspect
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

from securesystemslib.signer import CryptoSigner

from in_toto.models._signer import (
    load_crypto_signer_from_pkcs8_file as load_signer,
)
from in_toto.models._signer import load_public_key_from_file as load_pubkey

PEMS = Path(__file__).parent / "pems"


class SignerStore:
    """CryptoSigner and public key (dict) store for sign/verify tests."""

    rsa: CryptoSigner = load_signer(PEMS / "rsa_private_unencrypted.pem")
    rsa_pub: Dict[str, Any] = load_pubkey(PEMS / "rsa_public.pem")
    ecdsa: CryptoSigner = load_signer(PEMS / "ecdsa_private_unencrypted.pem")
    ecdsa_pub: Dict[str, Any] = load_pubkey(PEMS / "ecdsa_public.pem")
    ed25519: CryptoSigner = load_signer(
        PEMS / "ed25519_private_unencrypted.pem"
    )
    ed25519_pub: Dict[str, Any] = load_pubkey(PEMS / "ed25519_public.pem")


class TmpDirMixin:
    """Mixin with classmethods to create and change into a temporary directory,
    and to change back to the original CWD and remove the temporary directory.

    """

    @classmethod
    def set_up_test_dir(cls):
        """Back up CWD, and create and change into temporary directory."""
        cls.original_cwd = os.getcwd()
        cls.test_dir = os.path.realpath(tempfile.mkdtemp())
        os.chdir(cls.test_dir)

    @classmethod
    def tear_down_test_dir(cls):
        """Change back to original CWD and remove temporary directory."""
        os.chdir(cls.original_cwd)
        shutil.rmtree(cls.test_dir)


class GPGKeysMixin:
    """Mixin with classmethod to copy GPG rsa test keyring to a subdir 'rsa' in
    the CWD.

    """

    gnupg_home = "rsa"
    gpg_key_768c43 = "7b3abb26b97b655ab9296bd15b0bd02e1c768c43"
    gpg_key_85da58 = "8288ef560ed3795f9df2c0db56193089b285da58"
    gpg_key_0c8a17 = "8465a1e2e0fb2b40adb2478e18fb3f537e0c8a17"
    gpg_key_d92439 = "c5a0abe6ec19d0d65f85e2c39be9df5131d924e9"

    @classmethod
    def set_up_gpg_keys(cls):
        gpg_keys = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "gpg_keyrings", "rsa"
        )

        shutil.copytree(gpg_keys, os.path.join(os.getcwd(), cls.gnupg_home))


class CliTestCase(unittest.TestCase):
    """TestCase subclass providing a test helper that patches sys.argv with
    passed arguments and asserts a SystemExit with a return code equal
    to the passed status argument.

    Subclasses of CliTestCase require a class variable that stores the main
    function of the cli tool to test as staticmethod, e.g.:

    ```
    import tests.common
    from in_toto.in_toto_run import main as in_toto_run_main

    class TestInTotoRunTool(tests.common.CliTestCase):
      cli_main_func = staticmethod(in_toto_run_main)
      ...

    ```
    """

    cli_main_func = None

    def __init__(self, *args, **kwargs):
        """Constructor that checks for the presence of a callable cli_main_func
        class variable. And stores the filename of the module containing that
        function, to be used as first argument when patching sys.argv in
        self.assert_cli_sys_exit.
        """
        # subclasses of `CliTestCase` must assign the main function of the
        # tested cli tool using `staticmethod()`
        assert callable(self.cli_main_func)

        file_path = inspect.getmodule(self.cli_main_func).__file__
        self.file_name = os.path.basename(file_path)

        super().__init__(*args, **kwargs)

    def assert_cli_sys_exit(self, cli_args, status):
        """Test helper to mock command line call and assert return value.
        The passed args does not need to contain the command line tool's name.
        This is assessed from  `self.cli_main_func`
        """
        with (
            patch.object(sys, "argv", [self.file_name] + cli_args),
            self.assertRaises(SystemExit) as raise_ctx,
        ):
            self.cli_main_func()  # pylint: disable=not-callable

        self.assertEqual(raise_ctx.exception.code, status)
