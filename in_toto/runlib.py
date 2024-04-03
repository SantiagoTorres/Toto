# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  runlib.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  June 27, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides a wrapper for any command of the software supply chain.

  The wrapper performs the following tasks which are implemented in this
  library.

    - Record state of material (files the command is executed on)
    - Execute command
      - Capture stdout/stderr/return value of the executed command
    - Record state of product (files after the command was executed)
    - Return Metadata containing a Link object which can be can be signed
      and stored to disk
"""
import glob
import io
import logging
import os
import subprocess  # nosec
import sys
import tempfile
import time
from collections import defaultdict

import securesystemslib.exceptions
import securesystemslib.formats
import securesystemslib.gpg
import securesystemslib.hash
from securesystemslib.signer import Signature, Signer, SSlibSigner

import in_toto.exceptions
import in_toto.settings
from in_toto.formats import (
    _check_hex,
    _check_signing_key,
    _check_str,
    _check_str_list,
)
from in_toto.models._signer import GPGSigner
from in_toto.models.link import (
    FILENAME_FORMAT,
    FILENAME_FORMAT_SHORT,
    UNFINISHED_FILENAME_FORMAT,
    UNFINISHED_FILENAME_FORMAT_GLOB,
)
from in_toto.models.metadata import Envelope, Metablock, Metadata
from in_toto.resolver import (
    RESOLVER_FOR_URI_SCHEME,
    DirectoryResolver,
    FileResolver,
    OSTreeResolver,
    Resolver,
)

# Inherits from in_toto base logger (c.f. in_toto.log)
LOG = logging.getLogger(__name__)


def record_artifacts_as_dict(
    artifacts,
    exclude_patterns=None,
    base_path=None,
    follow_symlink_dirs=False,
    normalize_line_endings=False,
    lstrip_paths=None,
):
    """
    <Purpose>
      Hashes each file in the passed path list. If the path list contains
      paths to directories the directory tree(s) are traversed.

      The files a link command is executed on are called materials.
      The files that result form a link command execution are called
      products.

      Paths are normalized for matching and storing by left stripping "./"

      NOTE on exclude patterns:
        - Uses PathSpec to compile gitignore-style patterns, making use of the
          GitWildMatchPattern class (registered as 'gitwildmatch')

        - Patterns are checked for match against the full path relative to each
          path passed in the artifacts list

        - If a directory is excluded, all its files and subdirectories are also
          excluded

        - How it differs from .gitignore
              - No need to escape #
              - No ignoring of trailing spaces
              - No general negation with exclamation mark !
              - No special treatment of slash /
              - No special treatment of consecutive asterisks **

        - Exclude patterns are likely to become command line arguments or part of
          a config file.

    <Arguments>
      artifacts:
              A list of file or directory paths used as materials or products for
              the link command.

      exclude_patterns: (optional)
              Artifacts matched by the pattern are excluded from the result.
              Exclude patterns can be passed as argument or specified via
              ARTIFACT_EXCLUDE_PATTERNS setting (see `in_toto.settings`).
              If passed, patterns specified via settings are overriden.

      base_path: (optional)
              Change to base_path and record artifacts relative from there.
              If not passed, current working directory is used as base_path.
              NOTE: The base_path part of the recorded artifact is not included
              in the returned paths.

      follow_symlink_dirs: (optional)
              Follow symlinked dirs if the linked dir exists (default is False).
              The recorded path contains the symlink name, not the resolved name.
              NOTE: This parameter toggles following linked directories only,
              linked files are always recorded, independently of this parameter.
              NOTE: Beware of infinite recursions that can occur if a symlink
              points to a parent directory or itself.

      normalize_line_endings: (optional)
              If True, replaces windows and mac line endings with unix line
              endings before hashing the content of the passed files, for
              cross-platform support.

      lstrip_paths: (optional)
              If a prefix path is passed, the prefix is left stripped from
              the path of every artifact that contains the prefix.

    <Exceptions>
      OSError: cannot change to base path directory.
      ValueError: arguments are malformed.

    <Side Effects>
      Calls functions to generate cryptographic hashes.

    <Returns>
      A dictionary with file paths as keys and the files' hashes as values.

    """
    artifact_hashes = {}

    if not artifacts:
        return artifact_hashes

    if not base_path:
        base_path = in_toto.settings.ARTIFACT_BASE_PATH

    if not exclude_patterns:
        exclude_patterns = in_toto.settings.ARTIFACT_EXCLUDE_PATTERNS

    # Configure resolver with resolver specific arguments
    # FIXME: This should happen closer to the user boundary, where
    # resolver-specific config arguments are passed and global state is managed.
    RESOLVER_FOR_URI_SCHEME[FileResolver.SCHEME] = FileResolver(
        exclude_patterns,
        base_path,
        follow_symlink_dirs,
        normalize_line_endings,
        lstrip_paths,
    )

    # Configure resolver for OSTree
    RESOLVER_FOR_URI_SCHEME[OSTreeResolver.SCHEME] = OSTreeResolver(base_path)

    # Configure resolver for hashing directories as a single entry
    RESOLVER_FOR_URI_SCHEME[DirectoryResolver.SCHEME] = DirectoryResolver(
        exclude_patterns=exclude_patterns,
        follow_symlink_dirs=follow_symlink_dirs,
        normalize_line_endings=normalize_line_endings,
        lstrip_paths=lstrip_paths,
    )

    # Aggregate artifacts per resolver
    resolver_for_uris = defaultdict(list)
    for artifact in artifacts:
        resolver = Resolver.for_uri(artifact)
        resolver_for_uris[resolver].append(artifact)

    # Hash artifacts in a batch per resolver
    # FIXME: The behavior may change if we hash each artifact individually,
    # because the left-prefix duplicate check in FileResolver only works for the
    # artifacts hashed in one batch.
    for resolver, uris in resolver_for_uris.items():
        artifact_hashes.update(resolver.hash_artifacts(uris))

    # Clear resolvers to not preserve global state change beyond this function.
    # FIXME: This also clears resolver registered elsewhere. For now we
    # assume that we only modify RESOLVER_FOR_URI_SCHEME in this function.
    RESOLVER_FOR_URI_SCHEME.clear()

    return artifact_hashes


def _subprocess_run_duplicate_streams(cmd, timeout):
    """Helper to run subprocess and both print and capture standards streams.

    Caveat:
    * Might behave unexpectedly with interactive commands.
    * Might not duplicate output in real time, if the command buffers it (see
      e.g. `print("foo")` vs. `print("foo", flush=True)`).
    * Possible race condition on Windows when removing temporary files.

    """
    # Use temporary files as targets for child process standard stream redirects
    # They seem to work better (i.e. do not hang) than pipes, when using
    # interactive commands like `vi`.
    stdout_fd, stdout_name = tempfile.mkstemp()
    stderr_fd, stderr_name = tempfile.mkstemp()
    try:
        with io.open(  # pylint: disable=unspecified-encoding
            stdout_name, "r"
        ) as stdout_reader, os.fdopen(  # pylint: disable=unspecified-encoding
            stdout_fd, "w"
        ) as stdout_writer, io.open(  # pylint: disable=unspecified-encoding
            stderr_name, "r"
        ) as stderr_reader, os.fdopen(
            stderr_fd, "w"
        ) as stderr_writer:
            # Store stream results in mutable dict to update it inside nested helper
            streams = {"out": "", "err": ""}

            def _duplicate_streams():
                """Helper to read from child process standard streams, write their
                contents to parent process standard streams, and build up return values
                for outer function.
                """
                # Read until EOF but at most `io.DEFAULT_BUFFER_SIZE` bytes per call.
                # Reading and writing in reasonably sized chunks prevents us from
                # subverting a timeout, due to being busy for too long or indefinitely.
                stdout_part = stdout_reader.read(io.DEFAULT_BUFFER_SIZE)
                stderr_part = stderr_reader.read(io.DEFAULT_BUFFER_SIZE)
                sys.stdout.write(stdout_part)
                sys.stderr.write(stderr_part)
                sys.stdout.flush()
                sys.stderr.flush()
                streams["out"] += stdout_part
                streams["err"] += stderr_part

            # Start child process, writing its standard streams to temporary files
            proc = subprocess.Popen(  # pylint: disable=consider-using-with  # nosec
                cmd,
                stdout=stdout_writer,
                stderr=stderr_writer,
                universal_newlines=True,
            )
            proc_start_time = time.time()

            # Duplicate streams until the process exits (or times out)
            while proc.poll() is None:
                # Time out as Python's `subprocess.run` would do it
                if (
                    timeout is not None
                    and time.time() > proc_start_time + timeout
                ):
                    proc.kill()
                    proc.wait()
                    raise subprocess.TimeoutExpired(cmd, timeout)

                _duplicate_streams()

            # Read/write once more to grab everything that the process wrote between
            # our last read in the loop and exiting, i.e. breaking the loop.
            _duplicate_streams()

    finally:
        # The work is done or was interrupted, the temp files can be removed
        # FIXME: retry failed file removal once to maybe work around #547
        for name in (stdout_name, stderr_name):
            try:
                os.remove(name)
            except PermissionError:  # pragma: no cover
                time.sleep(0.01)
                os.remove(name)

    # Return process exit code and captured streams
    return proc.poll(), streams["out"], streams["err"]


def execute_link(link_cmd_args, record_streams, timeout):
    """
    <Purpose>
      Executes the passed command plus arguments in a subprocess and returns
      the return value of the executed command. If the specified standard output
      and standard error of the command are recorded and also returned to the
      caller.

    <Arguments>
      link_cmd_args:
              A list where the first element is a command and the remaining
              elements are arguments passed to that command.
      record_streams:
              A bool that specifies whether to redirect standard output and
              and standard error to a temporary file which is returned to the
              caller (True) or not (False).

    <Exceptions>
      OSError:
              The given command is not present or non-executable

      subprocess.TimeoutExpired:
              The execution of the given command times.

    <Side Effects>
      Executes passed command in a subprocess and redirects stdout and stderr
      if specified.

    <Returns>
      - A dictionary containing standard output and standard error of the
        executed command, called by-products.
        Note: If record_streams is False, the dict values are empty strings.
      - The return value of the executed command.
    """
    if record_streams:
        return_code, stdout_str, stderr_str = _subprocess_run_duplicate_streams(
            link_cmd_args, timeout=timeout
        )

    else:
        process = subprocess.run(
            link_cmd_args,
            check=False,  # nosec
            timeout=timeout,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        stdout_str = stderr_str = ""
        return_code = process.returncode

    return {
        "stdout": stdout_str,
        "stderr": stderr_str,
        "return-value": return_code,
    }


def in_toto_mock(name, link_cmd_args, use_dsse=False):
    """
    <Purpose>
      in_toto_run with defaults
       - Records materials and products in current directory
       - Does not sign resulting link file
       - Stores resulting link file under "<name>.link"

    <Arguments>
      name:
              A unique name to relate mock link metadata with a step or
              inspection defined in the layout.
      link_cmd_args:
              A list where the first element is a command and the remaining
              elements are arguments passed to that command.
      use_dsse (optional):
              A boolean indicating if DSSE should be used to generate metadata.

    <Exceptions>
      None.

    <Side Effects>
      Writes newly created link metadata file to disk using the filename scheme
      from link.FILENAME_FORMAT_SHORT

    <Returns>
      Newly created Metadata object containing a Link object

    """
    link_metadata = in_toto_run(
        name,
        ["."],
        ["."],
        link_cmd_args,
        record_streams=True,
        use_dsse=use_dsse,
    )

    filename = FILENAME_FORMAT_SHORT.format(step_name=name)
    LOG.info("Storing unsigned link metadata to '%s'...", filename)
    link_metadata.dump(filename)
    return link_metadata


def _check_signer(signer):
    if not isinstance(signer, Signer):
        raise ValueError("signer must be a Signer instance")


def _require_signing_arg(signer, signing_key, gpg_keyid, gpg_use_default):
    if not any([signer, signing_key, gpg_keyid, gpg_use_default]):
        raise ValueError(
            "Pass either a signer, a signing key, a gpg keyid or set"
            " gpg_use_default to True!"
        )


def in_toto_run(
    name,
    material_list,
    product_list,
    link_cmd_args,
    record_streams=False,
    signing_key=None,
    gpg_keyid=None,
    gpg_use_default=False,
    gpg_home=None,
    exclude_patterns=None,
    base_path=None,
    compact_json=False,
    record_environment=False,
    normalize_line_endings=False,
    lstrip_paths=None,
    metadata_directory=None,
    use_dsse=False,
    timeout=in_toto.settings.LINK_CMD_EXEC_TIMEOUT,
    signer=None,
):
    """Performs a supply chain step or inspection generating link metadata.

  Executes link_cmd_args, recording paths and hashes of files before and after
  command execution (aka. artifacts) in a link metadata file. The metadata is
  signed with the passed signer, signing_key, a gpg key identified by its ID, or
  the default gpg key. If multiple key arguments are passed, only one key is
  used in above order of precedence. The resulting link file is written to
  ``STEP-NAME.KEYID-PREFIX.link``. If no key argument is passed the link
  metadata is neither signed nor written to disk.

  Arguments:
    name: A unique name to associate link metadata with a step or inspection.

    material_list: A list of artifact paths to be recorded before command
        execution. Directories are traversed recursively.

    product_list: A list of artifact paths to be recorded after command
        execution. Directories are traversed recursively.

    link_cmd_args: A list where the first element is a command and the
        remaining elements are arguments passed to that command.

    record_streams (optional): A boolean indicating if standard output and
        standard error of the link command should be recorded in the link
        metadata in addition to being displayed while the command is executed.

    signing_key (optional): A key used to sign the resulting link metadata.

        .. deprecated:: 2.2.0
           Please pass a ``signer`` instead.

    gpg_keyid (optional): A keyid used to identify a local gpg key used to sign
        the resulting link metadata.

    gpg_use_default (optional): A boolean indicating if the default gpg key
        should be used to sign the resulting link metadata.

    gpg_home (optional): A path to the gpg home directory. If not set the
        default gpg home directory is used.

    exclude_patterns (optional): A list of filename patterns to exclude certain
        files from being recorded as artifacts. See Config docs for details.

    base_path (optional): A path relative to which artifacts are recorded.
        Default is the current working directory.

    compact_json (optional): A boolean indicating if the resulting link
        metadata should be written in the most compact JSON representation.

    record_environment (optional): A boolean indicating if information about
        the environment should be added in the resulting link metadata.

    normalize_line_endings (optional): A boolean indicating if line endings of
        artifacts should be normalized before hashing for cross-platform
        support.

    lstrip_paths (optional): A list of path prefixes used to left-strip
        artifact paths before storing them in the resulting link metadata.

    metadata_directory (optional): A directory path to write the resulting link
        metadata file to. Default destination is the current working directory.

    use_dsse (optional): A boolean indicating if DSSE should be used to
        generate metadata.

    timeout (optional): An integer indicating the max timeout in seconds
        for this command. Default is 10 seconds.

    signer (optional): A securesystemslib Signer instance used to
        sign the resulting link metadata.

  Raises:
    securesystemslib.exceptions.FormatError: Passed arguments are malformed.

    OSError: Cannot change to base path directory.

    securesystemslib.exceptions.StorageError: Cannot hash artifacts.

    PrefixError: Left-stripping artifact paths results in non-unique dict keys.

    subprocess.TimeoutExpired: Link command times out.

    IOError, FileNotFoundError, NotADirectoryError, PermissionError:
        Cannot write link metadata.

    securesystemslib.exceptions.CryptoError, \
            securesystemslib.exceptions.UnsupportedAlgorithmError:
        Signing errors.

    ValueError, OSError, securesystemslib.gpg.exceptions.CommandError, \
            securesystemslib.gpg.exceptions.KeyNotFoundError:
        gpg signing errors.

  Side Effects:
    Reads artifact files from disk.
    Runs link command in subprocess.
    Calls system gpg in a subprocess, if a gpg key argument is passed.
    Writes link metadata file to disk, if any key argument is passed.

  Returns:
    A Metadata object that contains the resulting link object.

  """
    # pylint: disable=too-many-branches, too-many-locals, too-many-statements

    LOG.info("Running '%s'...", name)

    # Check key formats to fail early
    if signer:
        _check_signer(signer)

    if signing_key:
        _check_signing_key(signing_key)

    if gpg_keyid:
        _check_hex(gpg_keyid)

    if exclude_patterns:
        _check_str_list(exclude_patterns)

    if base_path:
        _check_str(base_path)

    if metadata_directory:
        _check_str(metadata_directory)

    if material_list:
        LOG.info("Recording materials '%s'...", ", ".join(material_list))

    materials_dict = record_artifacts_as_dict(
        material_list,
        exclude_patterns=exclude_patterns,
        base_path=base_path,
        follow_symlink_dirs=True,
        normalize_line_endings=normalize_line_endings,
        lstrip_paths=lstrip_paths,
    )

    if link_cmd_args:
        _check_str_list(link_cmd_args)
        LOG.info("Running command '%s'...", " ".join(link_cmd_args))
        byproducts = execute_link(link_cmd_args, record_streams, timeout)
    else:
        byproducts = {}

    if product_list:
        _check_str_list(product_list)
        LOG.info("Recording products '%s'...", ", ".join(product_list))

    products_dict = record_artifacts_as_dict(
        product_list,
        exclude_patterns=exclude_patterns,
        base_path=base_path,
        follow_symlink_dirs=True,
        normalize_line_endings=normalize_line_endings,
        lstrip_paths=lstrip_paths,
    )

    LOG.info("Creating link metadata...")
    environment = {}
    if record_environment:
        environment["workdir"] = os.getcwd().replace("\\", "/")

    link = in_toto.models.link.Link(
        name=name,
        materials=materials_dict,
        products=products_dict,
        command=link_cmd_args,
        byproducts=byproducts,
        environment=environment,
    )

    if use_dsse:
        LOG.info("Generating link metadata using DSSE...")
        link_metadata = Envelope.from_signable(link)
    else:
        LOG.info("Generating link metadata using Metablock...")
        link_metadata = Metablock(signed=link, compact_json=compact_json)

    if signer:
        LOG.info("Signing link metadata using passed signer...")

    elif signing_key:
        LOG.info("Signing link metadata using passed key...")
        signer = SSlibSigner(signing_key)

    elif gpg_keyid:
        LOG.info("Signing link metadata using passed GPG keyid...")
        signer = GPGSigner(keyid=gpg_keyid, homedir=gpg_home)

    elif gpg_use_default:
        LOG.info("Signing link metadata using default GPG key ...")
        signer = GPGSigner(keyid=None, homedir=gpg_home)

    # We need the signature's keyid to write the link to keyid infix'ed filename
    if signer:
        signature = link_metadata.create_signature(signer)
        signing_keyid = signature.keyid

        filename = FILENAME_FORMAT.format(step_name=name, keyid=signing_keyid)

        if metadata_directory is not None:
            filename = os.path.join(metadata_directory, filename)

        LOG.info("Storing link metadata to '%s'...", filename)
        link_metadata.dump(filename)

    return link_metadata


def in_toto_record_start(
    step_name,
    material_list,
    signing_key=None,
    gpg_keyid=None,
    gpg_use_default=False,
    gpg_home=None,
    exclude_patterns=None,
    base_path=None,
    record_environment=False,
    normalize_line_endings=False,
    lstrip_paths=None,
    use_dsse=False,
    signer=None,
):
    """Generates preliminary link metadata.

  Records paths and hashes of materials in a preliminary link metadata file. The
  metadata is signed with the passed signer, signing_key, a gpg key identified
  by its ID, or the default gpg key. If multiple key arguments are passed, only
  one key is used in above order of precedence. At least one key argument must
  be passed. The resulting link file is written to
  ``.STEP-NAME.KEYID-PREFIX.link-unfinished``.

  Use this function together with in_toto_record_stop as an alternative to
  in_toto_run, in order to provide evidence for supply chain steps that cannot
  be carried out by a single command.

  Arguments:
    step_name: A unique name to associate link metadata with a step.

    material_list: A list of artifact paths to be recorded as materials.
        Directories are traversed recursively.

    signing_key (optional): A key used to sign the resulting link metadata.

        .. deprecated:: 2.2.0
           Please pass a ``signer`` instead.

    gpg_keyid (optional): A keyid used to identify a local gpg key used to sign
        the resulting link metadata.

    gpg_use_default (optional): A boolean indicating if the default gpg key
        should be used to sign the resulting link metadata.

    gpg_home (optional): A path to the gpg home directory. If not set the
        default gpg home directory is used.

    exclude_patterns (optional): A list of filename patterns to exclude certain
        files from being recorded as artifacts. See Config docs for details.

    base_path (optional): A path relative to which artifacts are recorded.
        Default is the current working directory.

    record_environment (optional): A boolean indicating if information about
        the environment should be added in the resulting link metadata.

    normalize_line_endings (optional): A boolean indicating if line endings of
        artifacts should be normalized before hashing for cross-platform
        support.

    lstrip_paths (optional): A list of path prefixes used to left-strip
        artifact paths before storing them in the resulting link metadata.

    use_dsse (optional): A boolean indicating if DSSE should be used to
        generate metadata.

    signer (optional): A securesystemslib Signer instance used to
        sign the resulting link metadata.

  Raises:
    securesystemslib.exceptions.FormatError: Passed arguments are malformed.

    ValueError: None of signing_key, gpg_keyid or gpg_use_default=True is
        passed.

    securesystemslib.exceptions.StorageError: Cannot hash artifacts.

    PrefixError: Left-stripping artifact paths results in non-unique dict keys.

    subprocess.TimeoutExpired: Link command times out.

    IOError, PermissionError:
        Cannot write link metadata.

    securesystemslib.exceptions.CryptoError, \
            securesystemslib.exceptions.UnsupportedAlgorithmError:
        Signing errors.

    ValueError, OSError, securesystemslib.gpg.exceptions.CommandError, \
            securesystemslib.gpg.exceptions.KeyNotFoundError:
        gpg signing errors.

  Side Effects:
    Reads artifact files from disk.
    Calls system gpg in a subprocess, if a gpg key argument is passed.
    Writes preliminary link metadata file to disk.

  """
    # pylint: disable=too-many-locals,too-many-branches

    LOG.info("Start recording '%s'...", step_name)

    # Fail if there is no signing key arg at all
    _require_signing_arg(signer, signing_key, gpg_keyid, gpg_use_default)

    # Check key formats to fail early
    if signer:
        _check_signer(signer)

    if signing_key:
        _check_signing_key(signing_key)

    if gpg_keyid:
        _check_str(gpg_keyid)

    if exclude_patterns:
        _check_str_list(exclude_patterns)

    if base_path:
        _check_str(base_path)

    if material_list:
        LOG.info("Recording materials '%s'...", ", ".join(material_list))

    materials_dict = record_artifacts_as_dict(
        material_list,
        exclude_patterns=exclude_patterns,
        base_path=base_path,
        follow_symlink_dirs=True,
        normalize_line_endings=normalize_line_endings,
        lstrip_paths=lstrip_paths,
    )

    LOG.info("Creating preliminary link metadata...")
    environment = {}
    if record_environment:
        environment["workdir"] = os.getcwd().replace("\\", "/")

    link = in_toto.models.link.Link(
        name=step_name,
        materials=materials_dict,
        products={},
        command=[],
        byproducts={},
        environment=environment,
    )

    if use_dsse:
        LOG.info("Generating link metadata using DSSE...")
        link_metadata = Envelope.from_signable(link)
    else:
        LOG.info("Generating link metadata using Metablock...")
        link_metadata = Metablock(signed=link)

    if signer:
        LOG.info("Signing link metadata using passed signer...")

    elif signing_key:
        LOG.info("Signing link metadata using passed key...")
        signer = SSlibSigner(signing_key)

    elif gpg_keyid:
        LOG.info("Signing link metadata using passed GPG keyid...")
        signer = GPGSigner(keyid=gpg_keyid, homedir=gpg_home)

    else:  # (gpg_use_default)
        LOG.info("Signing link metadata using default GPG key ...")
        signer = GPGSigner(keyid=None, homedir=gpg_home)

    signature = link_metadata.create_signature(signer)
    # We need the signature's keyid to write the link to keyid infix'ed filename
    signing_keyid = signature.keyid

    unfinished_fn = UNFINISHED_FILENAME_FORMAT.format(
        step_name=step_name, keyid=signing_keyid
    )

    LOG.info("Storing preliminary link metadata to '%s'...", unfinished_fn)
    link_metadata.dump(unfinished_fn)


def in_toto_record_stop(
    step_name,
    product_list,
    signing_key=None,
    gpg_keyid=None,
    gpg_use_default=False,
    gpg_home=None,
    exclude_patterns=None,
    base_path=None,
    normalize_line_endings=False,
    lstrip_paths=None,
    metadata_directory=None,
    command=None,
    byproducts=None,
    environment=None,
    signer=None,
):
    """Finalizes preliminary link metadata generated with in_toto_record_start.

  Loads preliminary link metadata file, verifies its signature, and records
  paths and hashes as products, thus finalizing the link metadata. The metadata
  is signed with the passed signer, signing_key, a gpg key identified by its ID,
  or the default gpg key. If multiple key arguments are passed, only one key is
  used in above order of precedence. At least one key argument must be passed
  and it must be the same as the one used to sign the preliminary link metadata
  file. The resulting link file is written to ``STEP-NAME.KEYID-PREFIX.link``.

  Use this function together with in_toto_record_start as an alternative to
  in_toto_run, in order to provide evidence for supply chain steps that cannot
  be carried out by a single command.

  Arguments:
    step_name: A unique name to associate link metadata with a step.

    product_list: A list of artifact paths to be recorded as products.
        Directories are traversed recursively.

    signing_key (optional): A key used to sign the resulting link metadata.

        .. deprecated:: 2.2.0
           Please pass a ``signer`` instead.

    gpg_keyid (optional): A keyid used to identify a local gpg key used to sign
        the resulting link metadata.

    gpg_use_default (optional): A boolean indicating if the default gpg key
        should be used to sign the resulting link metadata.

    gpg_home (optional): A path to the gpg home directory. If not set the
        default gpg home directory is used.

    exclude_patterns (optional): A list of filename patterns to exclude certain
        files from being recorded as artifacts.

    base_path (optional): A path relative to which artifacts are recorded.
        Default is the current working directory.

    normalize_line_endings (optional): A boolean indicating if line endings of
        artifacts should be normalized before hashing for cross-platform
        support.

    lstrip_paths (optional): A list of path prefixes used to left-strip
        artifact paths before storing them in the resulting link metadata.

    metadata_directory (optional): A directory path to write the resulting link
        metadata file to. Default destination is the current working directory.

    command (optional): A list consisting of a command and arguments executed
        between in_toto_record_start() and in_toto_record_stop() to capture
        the command ran in the resulting link metadata.

    byproducts (optional): A dictionary that lists byproducts of the link
        command execution. It should have at least the following entries
        "stdout" (str), "stderr" (str) and "return-value" (int).

    environment (optional): A dictionary to capture information about
        the environment to be added in the resulting link metadata eg.::

            {
              "variables": "<list of env var KEY=value pairs>",
              "filesystem": "<filesystem info>",
              "workdir": "<CWD when executing link command>"
            }

    signer (optional): A securesystemslib Signer instance used to
        sign the resulting link metadata.

  Raises:
    securesystemslib.exceptions.FormatError: Passed arguments are malformed.

    ValueError: None of signing_key, gpg_keyid or gpg_use_default=True is
        passed.

    LinkNotFoundError: No preliminary link metadata file found.

    securesystemslib.exceptions.StorageError: Cannot hash artifacts.

    PrefixError: Left-stripping artifact paths results in non-unique dict keys.

    subprocess.TimeoutExpired: Link command times out.

    IOError, FileNotFoundError, NotADirectoryError, PermissionError:
        Cannot write link metadata.

    securesystemslib.exceptions.CryptoError, \
            securesystemslib.exceptions.UnsupportedAlgorithmError:
        Signing errors.

    ValueError, OSError, securesystemslib.gpg.exceptions.CommandError, \
            securesystemslib.gpg.exceptions.KeyNotFoundError:
        gpg signing errors.

  Side Effects:
    Reads preliminary link metadata file from disk.
    Reads artifact files from disk.
    Calls system gpg in a subprocess, if a gpg key argument is passed.
    Writes resulting link metadata file to disk.
    Removes preliminary link metadata file from disk.

  """
    # pylint: disable=too-many-branches, too-many-locals, too-many-statements
    LOG.info("Stop recording '%s'...", step_name)

    # Check that we have something to sign and if the formats are right
    _require_signing_arg(signer, signing_key, gpg_keyid, gpg_use_default)

    if signer:
        _check_signer(signer)

    if signing_key:
        _check_signing_key(signing_key)

    if gpg_keyid:
        _check_hex(gpg_keyid)

    if exclude_patterns:
        _check_str_list(exclude_patterns)

    if base_path:
        _check_str(base_path)

    if metadata_directory:
        _check_str(metadata_directory)

    # Load preliminary link file
    # If we have a signing key we can use the keyid to construct the name
    if signer:
        unfinished_fn = UNFINISHED_FILENAME_FORMAT.format(
            step_name=step_name, keyid=signer.public_key.keyid
        )

    elif signing_key:
        unfinished_fn = UNFINISHED_FILENAME_FORMAT.format(
            step_name=step_name, keyid=signing_key["keyid"]
        )

    # FIXME: Currently there is no way to know the default GPG key's keyid and
    # so we glob for preliminary link files
    else:
        unfinished_fn_glob = UNFINISHED_FILENAME_FORMAT_GLOB.format(
            step_name=step_name, pattern="*"
        )
        unfinished_fn_list = glob.glob(unfinished_fn_glob)

        if not unfinished_fn_list:
            raise in_toto.exceptions.LinkNotFoundError(
                "Could not find a preliminary"
                " link for step '{}' in the current working directory.".format(
                    step_name
                )
            )

        if len(unfinished_fn_list) > 1:
            raise in_toto.exceptions.LinkNotFoundError(
                "Found more than one"
                " preliminary links for step '{}' in the current working directory:"
                " {}. We need exactly one to stop recording.".format(
                    step_name, ", ".join(unfinished_fn_list)
                )
            )

        unfinished_fn = unfinished_fn_list[0]

    LOG.info("Loading preliminary link metadata '%s'...", unfinished_fn)
    link_metadata = Metadata.load(unfinished_fn)

    # The file must have been signed by the same key
    # If we have a signing_key we use it for verification as well
    if signer:
        LOG.info("Verifying preliminary link signature using passed signer...")
        keyid = signer.public_key.keyid
        verification_key = signer.public_key.to_dict()
        verification_key["keyid"] = keyid

    elif signing_key:
        LOG.info(
            "Verifying preliminary link signature using passed signing key..."
        )
        keyid = signing_key["keyid"]
        verification_key = signing_key

    elif gpg_keyid:
        LOG.info("Verifying preliminary link signature using passed gpg key...")
        gpg_pubkey = securesystemslib.gpg.functions.export_pubkey(
            gpg_keyid, gpg_home
        )
        keyid = gpg_pubkey["keyid"]
        verification_key = gpg_pubkey

    else:  # must be gpg_use_default
        # FIXME: Currently there is no way to know the default GPG key's keyid
        # before signing. As a workaround we extract the keyid of the preliminary
        # Link file's signature and try to export a pubkey from the gpg
        # home directory. We do this even if a gpg_keyid was specified, because gpg
        # accepts many different ids (mail, name, parts of an id, ...) but we
        # need a specific format.
        LOG.info(
            "Verifying preliminary link signature using default gpg key..."
        )
        # signatures are objects in DSSE.
        sig = link_metadata.signatures[0]
        if isinstance(sig, Signature):
            keyid = sig.keyid
        else:
            keyid = sig["keyid"]
        gpg_pubkey = securesystemslib.gpg.functions.export_pubkey(
            keyid, gpg_home
        )
        verification_key = gpg_pubkey

    link_metadata.verify_signature(verification_key)

    LOG.info("Extracting Link from metadata...")
    link = link_metadata.get_payload()

    # Record products if a product path list was passed
    if product_list:
        LOG.info("Recording products '%s'...", ", ".join(product_list))

    link.products = record_artifacts_as_dict(
        product_list,
        exclude_patterns=exclude_patterns,
        base_path=base_path,
        follow_symlink_dirs=True,
        normalize_line_endings=normalize_line_endings,
        lstrip_paths=lstrip_paths,
    )

    if command:
        link.command = command

    if byproducts:
        link.byproducts = byproducts

    if environment:
        link.environment = environment

    if isinstance(link_metadata, Metablock):
        LOG.info("Generating link metadata using Metablock...")
        link_metadata = Metablock(signed=link)
    else:
        LOG.info("Generating link metadata using DSSE...")
        link_metadata = Envelope.from_signable(link)

    if signer:
        LOG.info(
            "Updating signature with signer '{:.8}...'...".format(
                signer.public_key.keyid
            )
        )

    elif signing_key:
        LOG.info("Updating signature with key '{:.8}...'...".format(keyid))
        signer = SSlibSigner(signing_key)

    else:  # gpg_keyid or gpg_use_default
        # In both cases we use the keyid we got from verifying the preliminary
        # link signature above.
        LOG.info("Updating signature with gpg key '{:.8}...'...".format(keyid))
        signer = GPGSigner(keyid=keyid, homedir=gpg_home)

    link_metadata.create_signature(signer)
    fn = FILENAME_FORMAT.format(step_name=step_name, keyid=keyid)

    if metadata_directory is not None:
        fn = os.path.join(metadata_directory, fn)

    LOG.info("Storing link metadata to '%s'...", fn)
    link_metadata.dump(fn)

    LOG.info("Removing unfinished link metadata '%s'...", unfinished_fn)
    os.remove(unfinished_fn)


def in_toto_match_products(
    link, paths=None, exclude_patterns=None, lstrip_paths=None
):
    """Check if local artifacts match products in passed link.

    NOTE: Does not check integrity or authenticity of passed link!

    Arguments:
      link: The Link object to match.

    See ``in_toto_run`` for details about arguments, and exceptions that may
    occur while recording artifact hashes.

    Returns:
      A 3-tuple with artifact names that are
      - only in products,
      - not in products,
      - have different hashes.
    """
    if paths is None:
        paths = ["."]

    artifacts = record_artifacts_as_dict(
        paths, exclude_patterns=exclude_patterns, lstrip_paths=lstrip_paths
    )

    artifact_names = artifacts.keys()
    product_names = link.products.keys()

    only_products = product_names - artifact_names
    not_in_products = artifact_names - product_names
    differ = {
        name
        for name in product_names & artifact_names
        if link.products[name] != artifacts[name]
    }

    return only_products, not_in_products, differ
