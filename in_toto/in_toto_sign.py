#!/usr/bin/env python

# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  in_toto_sign.py

<Author>
  Sachit Malik <i.sachitmalik@gmail.com>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  June 13, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides command line interface to sign in-toto link or layout metadata
  or to verify its signatures.

"""
import argparse
import logging
import sys
from getpass import getpass

from securesystemslib._gpg import functions as gpg_interface

from in_toto import __version__, exceptions
from in_toto.common_args import (
    GPG_HOME_ARGS,
    GPG_HOME_KWARGS,
    QUIET_ARGS,
    QUIET_KWARGS,
    VERBOSE_ARGS,
    VERBOSE_KWARGS,
    sort_action_groups,
    title_case_action_groups,
)
from in_toto.formats import _check_hex
from in_toto.models._signer import (
    GPGSigner,
    load_crypto_signer_from_pkcs8_file,
    load_public_key_from_file,
)
from in_toto.models.link import FILENAME_FORMAT
from in_toto.models.metadata import Metadata

# Command line interfaces should use in_toto base logger (c.f. in_toto.log)
LOG = logging.getLogger("in_toto")


def _sign_and_dump_metadata(metadata, args):
    """
    <Purpose>
      Internal method to sign link or layout metadata and dump it to disk.

    <Arguments>
      metadata:
              Metadata object (contains Link or Layout object)
      args:
              see argparser

    <Exceptions>
      SystemExit(0) if signing is successful
      SystemExit(2) if any exception occurs

    """

    try:
        if not args.append:
            metadata.signatures.clear()

        signature = None
        # If the cli tool was called with `--gpg [KEYID ...]` `args.gpg` is
        # a list (not None) and we will try to sign with gpg.
        # If `--gpg-home` was not set, args.gpg_home is None and the signer tries
        # to use the default gpg keyring.
        if args.gpg is not None:
            # If `--gpg` was passed without argument we sign with the default key
            # Excluded so that coverage does not vary in different test environments
            if len(args.gpg) == 0:  # pragma: no cover
                signature = metadata.create_signature(
                    GPGSigner(None, homedir=args.gpg_home)
                )

            # Otherwise we sign with each passed keyid
            for keyid in args.gpg:
                _check_hex(keyid)
                signature = metadata.create_signature(
                    GPGSigner(keyid, homedir=args.gpg_home)
                )

        # Alternatively we iterate over passed private key paths `--key KEYPATH
        # ...` load the corresponding key from disk and sign with it
        elif args.key is not None:  # pragma: no branch
            password = None
            if args.prompt:
                password = getpass()
                password = password.encode()

            for path in args.key:
                signer = load_crypto_signer_from_pkcs8_file(path, password)
                signature = metadata.create_signature(signer)

        payload = metadata.get_payload()
        _type = payload.type_

        # If `--output` was specified we store the signed link or layout metadata
        # to that location no matter what
        if args.output:
            out_path = args.output

        # Otherwise, in case of links, we build the filename using the link/step
        # name and the keyid of the created signature (there is only one for links)
        elif _type == "link":
            keyid = signature.keyid
            out_path = FILENAME_FORMAT.format(
                step_name=payload.name, keyid=keyid
            )

        # In case of layouts we just override the input file.
        elif _type == "layout":
            out_path = args.file

        else:  # pragma: no cover
            raise ValueError("invalid type {_type}")  # unreachable

        LOG.info("Dumping %s to '%s'...", _type, out_path)

        metadata.dump(out_path)
        sys.exit(0)

    except Exception as e:  # pylint: disable=broad-exception-caught
        LOG.error("The following error occurred while signing: %s", e)
        sys.exit(2)


def _verify_metadata(metadata, args):
    """
    <Purpose>
      Internal method to verify link or layout signatures.

    <Arguments>
      metadata:
              Metadata object (contains Link or Layout object)
      args:
              see argparser

    <Exceptions>
      SystemExit(0) if verification passes
      SystemExit(1) if verification fails
      SystemExit(2) if any exception occurs

    """
    try:
        # Load pubkeys from disk ....
        if args.key is not None:
            pub_key_dict = {}
            for path in args.key:
                key = load_public_key_from_file(path)
                pub_key_dict[key["keyid"]] = key

        # ... or from gpg keyring
        elif args.gpg is not None:  # pragma: no branch
            pub_key_dict = gpg_interface.export_pubkeys(args.gpg, args.gpg_home)

        for keyid, verification_key in pub_key_dict.items():
            metadata.verify_signature(verification_key)
            LOG.info("Signature verification passed for keyid '%s'", keyid)

        sys.exit(0)

    except exceptions.SignatureVerificationError as e:
        LOG.error("Signature verification failed: %s", e)
        sys.exit(1)

    except Exception as e:  # pylint: disable=broad-exception-caught
        LOG.error(
            "The following error occurred while verifying signatures: %s", e
        )
        sys.exit(2)


def _load_metadata(file_path):
    """
    <Purpose>
      Loads Metadata (link or layout metadata) file from disk

    <Arguments>
      file_path:
              path to link or layout metadata file

    <Exceptions>
      SystemExit(2) if any exception occurs

    <Returns>
      in-toto Metadata object (contains Link or Layout object)

    """
    try:
        return Metadata.load(file_path)

    except Exception as e:  # pylint: disable=broad-exception-caught
        LOG.error(
            "The following error occurred while loading the file '%s': %s",
            file_path,
            e,
        )
        sys.exit(2)


def create_parser():
    """Create and return configured ArgumentParser instance."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
in-toto-sign provides a command line interface to sign in-toto link or layout
metadata or verify their signatures, with options to:

  * replace (default) or add signatures:

    + layout metadata can be signed by multiple keys at once,
    + link metadata can only be signed by one key at a time.

  * write signed metadata to a specified path. If no output path is specified,

    + layout metadata is written to the path of the input file,
    + link metadata is written to '<name>.<keyid prefix>.link'.

  * verify signatures

in-toto-sign is useful to re-sign metadata (e.g. when changing keys), or to
sign unsigned links (e.g. generated with 'in-toto-mock'). For layouts, it is
useful to append signatures in case threshold signing of layouts is necessary.

It returns a non-zero value on failure and zero otherwise.""",
    )

    parser.epilog = """EXAMPLE USAGE

Sign 'unsigned.layout' with two keys and write it to 'root.layout'.

  {prog} -f unsigned.layout -k priv_key1 priv_key2 -o root.layout


Replace signature in link file and write to default filename, i.e.
'package.<priv_key keyid prefix>.link'.

  {prog} -f package.2f89b927.link -k priv_key


Verify layout signed with 3 keys.

  {prog} -f root.layout -k pub_key0 pub_key1 pub_key2 --verify


Sign layout with default gpg key in default gpg keyring.

  {prog} -f root.layout --gpg


Verify layout with a gpg key identified by keyid '...439F3C2'.

  {prog} -f root.layout --verify \\
      --gpg 3BF8135765A07E21BD12BF89A5627F6BF439F3C2

""".format(
        prog=parser.prog
    )

    named_args = parser.add_argument_group("required named arguments")

    named_args.add_argument(
        "-f",
        "--file",
        type=str,
        required=True,
        metavar="<path>",
        help=("path to link or layout file to be signed or verified."),
    )

    parser.add_argument(
        "-k",
        "--key",
        nargs="+",
        metavar="<path>",
        help=(
            "paths to key files, used to sign the passed link or layout metadata"
            " or to verify its signatures. Verification keys are expected in"
            " PEM/subjectPublicKeyInfo and signing keys in PEM/PKCS8 format."
            " Pass '--prompt' to enter a signing key decryption password."
        ),
    )

    parser.add_argument(
        "-p",
        "--prompt",
        action="store_true",
        help="prompt for signing key decryption password",
    )

    parser.add_argument(
        "-g",
        "--gpg",
        nargs="*",
        metavar="<id>",
        help=(
            "GPG keyids used to sign the passed link or layout metadata or to verify"
            " its signatures. If passed without keyids, the default GPG key is"
            " used."
        ),
    )

    parser.add_argument(*GPG_HOME_ARGS, **GPG_HOME_KWARGS)

    # Only when signing
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        metavar="<path>",
        help=(
            "path to location where the metadata file is stored after signing. If"
            " not passed, layout metadata is written to the path of the input file"
            " and link metadata is written to '<name>.<keyid prefix>.link'"
        ),
    )

    # Only when signing
    parser.add_argument(
        "-a",
        "--append",
        action="store_true",
        help=(
            "add signatures rather than replacing existing signatures. This option"
            " is only availabe for layout metdata."
        ),
    )

    parser.add_argument(
        "--verify",
        action="store_true",
        help="verify signatures of passed link or layout metadata using the"
        " public keys passed via '--key' and/or '--gpg' options.",
    )

    verbosity_args = parser.add_mutually_exclusive_group(required=False)
    verbosity_args.add_argument(*VERBOSE_ARGS, **VERBOSE_KWARGS)
    verbosity_args.add_argument(*QUIET_ARGS, **QUIET_KWARGS)

    parser.add_argument(
        "--version",
        action="version",
        version="{} {}".format(parser.prog, __version__),
    )

    title_case_action_groups(parser)
    sort_action_groups(parser)

    return parser


def main():
    """Parse arguments, load link or layout metadata file and either sign
    metadata file or verify its signatures."""

    parser = create_parser()
    args = parser.parse_args()

    LOG.setLevelVerboseOrQuiet(args.verbose, args.quiet)

    # Additional argparse sanitization
    # NOTE: This tool is starting to have many inter-dependent argument
    # restrictions. Maybe we should make it less sophisticated at some point.
    if args.verify and (args.append or args.output):
        parser.print_help()
        parser.error(
            "conflicting arguments: don't specify any of"
            " 'append' or 'output' when verifying signatures"
        )

    # Regular signing and GPG signing are mutually exclusive
    if (args.key is None) == (args.gpg is None):
        parser.print_help()
        parser.error(
            "wrong arguments: specify either '--key PATH [PATH ...]'"
            " or '--gpg [KEYID [KEYID ...]]'"
        )

    # For gpg verification we must specify a keyid (no default key is loaded)
    if args.verify and args.gpg is not None and len(args.gpg) < 1:
        parser.print_help()
        parser.error(
            "missing arguments: specify at least one keyid for GPG"
            " signature verification ('--gpg KEYID ...')"
        )

    metadata = _load_metadata(args.file)

    # Specific command line argument restrictions if we deal with links
    payload = metadata.get_payload()
    if payload.type_ == "link":
        # Above we check that it's either `--key ...` or `--gpg ...`
        # Here we check that it is not more than one in each case when dealing
        # with links
        link_error_message = (
            "link metadata is associated with a"
            " single functionary and is usually namespaced accordingly:"
            " '<name>.<keyid prefix>.link'."
        )

        if (args.key is not None and len(args.key) > 1) or (
            args.gpg is not None and len(args.gpg) > 1
        ):
            parser.print_help()
            parser.error(
                "too many arguments: {} Hence signing Link metadata"
                " with multiple keys is not allowed.".format(link_error_message)
            )

        if args.append:
            parser.print_help()
            parser.error(
                "wrong arguments: {}. Hence adding signatures to"
                " existing signatures on link metadata is not allowed.".format(
                    link_error_message
                )
            )

    if args.verify:
        _verify_metadata(metadata, args)

    else:
        _sign_and_dump_metadata(metadata, args)


if __name__ == "__main__":
    main()
