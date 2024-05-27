# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  verifylib.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>
  Santiago Torres-Arias <santiago@nyu.edu>

<Started>
  June 28, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>

  Provides a library to verify an in-toto final product containing
  a software supply chain layout.

  Take a look at `in_toto_verify`'s docstring for more details about the
  entire verification workflow.

"""

import datetime
import fnmatch
import logging
import os

import iso8601
import securesystemslib.exceptions
import securesystemslib.formats
from dateutil import tz
from securesystemslib._gpg.exceptions import KeyExpirationError

import in_toto.formats
import in_toto.models.layout
import in_toto.models.link
import in_toto.rulelib
import in_toto.runlib
import in_toto.settings
from in_toto.exceptions import (
    BadReturnValueError,
    LayoutExpiredError,
    RuleVerificationError,
    SignatureVerificationError,
    ThresholdVerificationError,
)
from in_toto.formats import _check_parameter_dict, _check_public_keys
from in_toto.models.metadata import Metadata

# Inherits from in_toto base logger (c.f. in_toto.log)
LOG = logging.getLogger(__name__)

RULE_TRACE = {}


def _raise_on_bad_retval(return_value, command=None):
    """
    <Purpose>
      Internal function that checks return values of shell commands, e.g. from
      inspections. Raises exception if the passed value is non-int and non-zero.

    <Arguments>
      return_value:
              The return value to be verified
      command: (optional)
              The command whose execution returned the value, used for exception
              message.

    <Exceptions>
      BadReturnValueError if the return_value is non-int and non-zero

    <Side Effects>
      None.

    <Returns>
      None.
    """

    msg = "Got non-{what} " + "return value '{}'".format(return_value)
    if command:
        msg = "{0} from command '{1}'.".format(msg, command)
    else:
        msg = "{0}.".format(msg)

    if not isinstance(return_value, int):
        raise BadReturnValueError(msg.format(what="int"))

    # TODO: in-toto specification suggests special behavior on
    # return_value == 127, but does not fully define that behavior yet

    if return_value != 0:
        raise BadReturnValueError(msg.format(what="zero"))


def load_links_for_layout(layout, link_dir_path):
    """
    <Purpose>
      Try to load all existing metadata files for each Step of the Layout
      from the current directory.

      For each step the metadata might consist of multiple (thresholds) Link
      or Layout (sub-layouts) files.

    <Arguments>
      layout:
            Layout object

      link_dir_path:
            A path to directory where links are loaded from


    <Side Effects>
      Calls function to read files from disk

    <Exceptions>
      in_toto.exceptions.LinkNotFoundError,
              if fewer than `threshold` link files can be found for any given
              step of the supply chain (preliminary threshold check)

    <Returns>
      A dictionary carrying all the found metadata corresponding to the
      passed layout, e.g.:

      {
        <step name> : {
          <functionary key id> : <Metadata containing a Link or Layout object>,
          ...
        }, ...
      }


    """
    steps_metadata = {}

    # Iterate over all the steps in the layout
    for step in layout.steps:
        links_per_step = {}

        # We try to load a link for every authorized functionary, but don't fail
        # if the file does not exist (authorized != required)
        # FIXME: Should we really pass on IOError, or just skip inexistent links?
        for authorized_keyid in step.pubkeys:
            # Iterate over the authorized key and if present over subkeys
            for keyid in [authorized_keyid] + list(
                layout.keys.get(authorized_keyid, {}).get("subkeys", {}).keys()
            ):
                filename = in_toto.models.link.FILENAME_FORMAT.format(
                    step_name=step.name, keyid=keyid
                )
                filepath = os.path.join(link_dir_path, filename)

                try:
                    metadata = Metadata.load(filepath)
                    links_per_step[keyid] = metadata

                except IOError:
                    pass

        # This is only a preliminary threshold check, based on (authorized)
        # filenames, to fail early. A more thorough signature-based threshold
        # check is indispensable.
        if len(links_per_step) < step.threshold:
            raise in_toto.exceptions.LinkNotFoundError(
                "Step '{0}' requires '{1}'"
                " link metadata file(s), found '{2}'.".format(
                    step.name, step.threshold, len(links_per_step)
                )
            )

        steps_metadata[step.name] = links_per_step

    return steps_metadata


def run_all_inspections(
    layout,
    persist_inspection_links,
    timeout=in_toto.settings.LINK_CMD_EXEC_TIMEOUT,
):
    """
    <Purpose>
      Extracts all inspections from a passed Layout's inspect field and
      iteratively runs each command defined in the Inspection's `run` field using
      `runlib.in_toto_run`, which returns a Link object.

      If a link command returns non-zero the verification is aborted.

    <Arguments>
      layout:
              A Layout object which is used to extract the Inspections.

      persist_inspection_links:
              A boolean indicating whether link metadata files for inspection
              are written to cwd.

      timeout:
              Integer that is the amount of seconds that the inspection run will
              fail after.

    <Exceptions>
      Calls function that raises BadReturnValueError if an inspection returned
      non-int or non-zero.

    <Returns>
      A dictionary of metadata about the executed inspections, e.g.:

      {
        <inspection name> : {
          <Link object>,
          ...
        }, ...
      }

    """
    inspection_links_dict = {}
    for inspection in layout.inspect:
        LOG.info("Executing command for inspection '%s'...", inspection.name)

        # FIXME: We don't want to use the base path for runlib so we patch this
        # for now. This will not stay!
        base_path_backup = in_toto.settings.ARTIFACT_BASE_PATH
        in_toto.settings.ARTIFACT_BASE_PATH = None

        # FIXME: What should we record as material/product?
        # Is the current directory a sensible default? In general?
        # If so, we should probably make it a default in run_link
        # We could use artifact rule paths.
        material_list = product_list = ["."]
        link = in_toto.runlib.in_toto_run(
            inspection.name,
            material_list,
            product_list,
            inspection.run,
            timeout=timeout,
        )

        _raise_on_bad_retval(
            link.signed.byproducts.get("return-value"), inspection.run
        )

        inspection_links_dict[inspection.name] = link.signed

        # If client requests persistent inspection links,
        # Dump the inspection link file for auditing
        # Keep in mind that this pollutes the verifier's (client's) filesystem.
        if persist_inspection_links:
            filename = in_toto.models.link.FILENAME_FORMAT_SHORT.format(
                step_name=inspection.name
            )
            link.dump(filename)

        in_toto.settings.ARTIFACT_BASE_PATH = base_path_backup

    return inspection_links_dict


def verify_layout_expiration(layout):
    """
    <Purpose>
      Raises an exception if the passed layout has expired, i.e. if its
      `expires` property is lesser "now".
      Time zone aware datetime objects in UTC+00:00 (Zulu Time) are used.

    <Arguments>
      layout:
              The Layout object to be verified.

    <Exceptions>
      LayoutExpiredError
      TBA (see https://github.com/in-toto/in-toto/issues/6)

    <Side Effects>
      None.

    """
    expire_datetime = iso8601.parse_date(layout.expires)
    if expire_datetime <= datetime.datetime.now(tz.tzutc()):
        raise LayoutExpiredError("Layout expired")


def substitute_parameters(layout, parameter_dictionary):
    """
    <Purpose>
      This function is a transitionary measure for parameter substitution (or
      any other solution defined by the in-toto team). As of now, it acts as
      a very simple replacement layer for python-like parameters

    <Arguments>
      layout:
              The Layout object to process.

        parameter_dictionary:
              A dictionary containing key-value pairs for substitution.

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        if the parameter dictionary is malformed.

      KeyError:
        if one of the keys in the parameter dictionary are not present for
        substitution

    <Side Effects>
      The layout object will have any tags replaced with the corresponding
      values defined in the parameter dictionary.
    """
    _check_parameter_dict(parameter_dictionary)

    for step in layout.steps:
        new_material_rules = []
        for rule in step.expected_materials:
            new_rule = []
            for stanza in rule:
                new_rule.append(stanza.format(**parameter_dictionary))
            new_material_rules.append(new_rule)

        new_product_rules = []
        for rule in step.expected_products:
            new_rule = []
            for stanza in rule:
                new_rule.append(stanza.format(**parameter_dictionary))
            new_product_rules.append(new_rule)

        new_expected_command = []
        for argv in step.expected_command:
            new_expected_command.append(argv.format(**parameter_dictionary))

        step.expected_command = new_expected_command
        step.expected_materials = new_material_rules
        step.expected_products = new_product_rules

    for inspection in layout.inspect:
        new_material_rules = []
        for rule in inspection.expected_materials:
            new_rule = []
            for stanza in rule:
                new_rule.append(stanza.format(**parameter_dictionary))
            new_material_rules.append(new_rule)

        new_product_rules = []
        for rule in inspection.expected_products:
            new_rule = []
            for stanza in rule:
                new_rule.append(stanza.format(**parameter_dictionary))
            new_product_rules.append(new_rule)

        new_run = []
        for argv in inspection.run:
            new_run.append(argv.format(**parameter_dictionary))

        inspection.run = new_run
        inspection.expected_materials = new_material_rules
        inspection.expected_products = new_product_rules


def verify_metadata_signatures(metadata, keys):
    """
    <Purpose>
      Iteratively verifies the signatures of a Metadata object containing
      a Layout object for every verification key in the passed keys list.

      Requires at least one key to be passed and requires every passed key to
      find a valid signature.

    <Arguments>
      metadata:
              A Metadata object containing a Layout whose signatures are
              verified.

      keys:
              A list of Key instances to verify the signatures.

    <Exceptions>
      securesystemslib.exceptions.FormatError
        if the passed keys list is invalid.

      SignatureVerificationError
        if an empty verification key list was passed, or
        if any of the passed verification keys fails to verify a signature.

      securesystemslib._gpg.exceptions.KeyExpirationError:
        if any of the passed verification keys is an expired gpg key

    """
    # Fail if an empty verification key list was passed
    if len(keys) < 1:
        raise SignatureVerificationError(
            "Layout signature verification requires at least one key."
        )

    # Fail if any of the passed keys can't verify a signature on the Layout
    for verify_key in keys:
        metadata.verify_signature(verify_key)


def verify_link_signature_thresholds(layout, steps_metadata):
    """
    <Purpose>
      Verify that for each step of the layout there are at least `threshold`
      links metadata, signed by different authorized functionaries and return the
      verified link metadata dictionary containing only authorized links metadata
      whose signatures were successfully verified.

      NOTE: If the layout's key store (`layout.keys`) lists a (master) key `K`,
      with a subkey `K'`, then `K'` is authorized implicitly, to sign any link
      that `K` is authorized to sign. In other words, the trust in a master key
      extends to the trust in a subkey. The inverse is not true.

    <Arguments>
      layout:
              A Layout object whose Steps are extracted and verified.

      steps_metadata:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Metadata containing a Link or Layout
                                          object>,
                  ...
                }, ...
              }

    <Exceptions>
      ThresholdVerificationError
              If any of the steps of the passed layout does not have enough
              (`step.threshold`) links signed by different authorized
              functionaries.

    <Returns>
      A steps_metadata containing only links with valid signatures created by
      authorized functionaries.

    """
    # pylint: disable=too-many-branches, too-many-locals

    # Create an inverse keys-subkeys dictionary, with subkey keyids as
    # dictionary keys and main keys as dictionary values. This will be
    # required below to assess main-subkey trust delegations.
    # We assume that a given subkey can only belong to one master key
    # TODO: Is this a safe assumption? Should we assert for it?
    main_keys_for_subkeys = {}
    for main_key in list(layout.keys.values()):
        for sub_keyid in main_key.get("subkeys", []):
            main_keys_for_subkeys[sub_keyid] = main_key

    # Dict for valid and authorized links of all steps of the layout
    verified_steps_metadata = {}

    # For each step of the layout check the signatures of corresponding links.
    # Consider only links where the signature is valid and keys are authorized,
    # and discard others.
    # Only count one of multiple links signed with different subkeys of a main
    # key towards link threshold.
    # Only proceed with final product verification if threshold requirements are
    # fulfilled.
    for step in layout.steps:
        # Dict for valid and authorized links of a given step
        verified_key_link_dict = {}
        # List of used keyids
        used_main_keyids = []

        # Do per step link threshold verification
        for link_keyid, link in steps_metadata.get(step.name, {}).items():
            # Iterate over authorized keyids to find a key or subkey corresponding
            # to the given link and check if the link's keyid is authorized.
            # Subkeys of authorized main keys are authorized implicitly.
            for authorized_keyid in step.pubkeys:
                authorized_key = layout.keys.get(authorized_keyid)
                main_key_for_subkey = main_keys_for_subkeys.get(
                    authorized_keyid
                )

                # The signing key is authorized ...
                if authorized_key and link_keyid == authorized_keyid:
                    verification_key = authorized_key
                    break

                # ... or the signing key is an authorized subkey ...
                if main_key_for_subkey and link_keyid == authorized_keyid:
                    verification_key = main_key_for_subkey
                    break

                # ... or the signing key is a subkey of an authorized key
                if (
                    authorized_key
                    and link_keyid in authorized_key.get("subkeys", {}).keys()
                ):
                    verification_key = authorized_key
                    break

            else:
                LOG.info(
                    "Skipping link. Keyid '%s' is not authorized to sign links"
                    " for step '%s'",
                    link_keyid,
                    step.name,
                )
                continue

            # Verify signature and skip invalidly signed links
            try:
                link.verify_signature(verification_key)

            except SignatureVerificationError:
                LOG.info(
                    "Skipping link. Broken link signature with keyid '%s'"
                    " for step '%s'",
                    link_keyid,
                    step.name,
                )
                continue

            except KeyExpirationError as e:
                LOG.info("Skipping link. %s", e)
                continue

            # Warn if there are links signed by different subkeys of same main key
            if verification_key["keyid"] in used_main_keyids:
                LOG.warning(
                    "Found links signed by different subkeys of the same main"
                    " key '%s' for step '%s'. Only one of them is counted towards the"
                    " step threshold.",
                    verification_key["keyid"],
                    step.name,
                )

            used_main_keyids.append(verification_key["keyid"])

            # Keep only links with valid and authorized signature
            verified_key_link_dict[link_keyid] = link

        # For each step, verify that we have enough validly signed links from
        # distinct authorized functionaries. Links signed by different subkeys of
        # the same main key are counted only once towards the threshold.
        valid_authorized_links_cnt = len(set(used_main_keyids))
        # TODO: To guarantee that links are signed by different functionaries
        # we rely on the layout to not carry duplicate verification keys under
        # different dictionary keys, e.g. {keyid1: KEY1, keyid2: KEY1}
        # Maybe we should add such a check to the layout validation? Or here?
        if valid_authorized_links_cnt < step.threshold:
            raise ThresholdVerificationError(
                "Step '{}' requires at least '{}' links"
                " validly signed by different authorized functionaries. Only"
                " found '{}'".format(
                    step.name, step.threshold, valid_authorized_links_cnt
                )
            )

        # Add all good links of this step to the dictionary of links of all steps
        verified_steps_metadata[step.name] = verified_key_link_dict

    # Threshold verification succeeded, return valid and authorized links for
    # further verification
    return verified_steps_metadata


def verify_command_alignment(command, expected_command):
    """
    <Purpose>
      Checks if a run command aligns with an expected command. The commands align
      if all of their elements are equal. If alignment fails, a warning is
      printed.

      Note:
        Command alignment is a weak guarantee. Because a functionary can easily
        alias commands.

    <Arguments>
      command:
              A command list, e.g. ["vi", "foo.py"]
      expected_command:
              A command list, e.g. ["make", "install"]

    <Exceptions>
      None.

    <Side Effects>
      Logs warning in case commands do not align.

    """
    # In what case command alignment should fail and how that failure should be
    # propagated has been thoughly discussed in:
    # https://github.com/in-toto/in-toto/issues/46 and
    # https://github.com/in-toto/in-toto/pull/47
    # We chose the simplest solution for now, i.e. Warn if they do not align.
    if command != expected_command:
        LOG.warning(
            "Run command '%s' differs from expected command '%s'",
            command,
            expected_command,
        )


def verify_all_steps_command_alignment(layout, chain_link_dict):
    """
    <Purpose>
      Iteratively checks if all expected commands as defined in the
      Steps of a Layout align with the actual commands as recorded in the Link
      metadata.

    <Arguments>
      layout:
              A Layout object to extract the expected commands from.

      chain_link_dict:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Link object>,
                  ...
                }, ...
              }

    <Exceptions>
      None.

    <Side Effects>
      None.

    """
    for step in layout.steps:
        # Find the according link for this step
        expected_command = step.expected_command
        key_link_dict = chain_link_dict[step.name]

        # FIXME: I think we could do this for one link per step only
        # providing that we verify command alignment AFTER threshold equality
        for keyid, link in key_link_dict.items():
            LOG.info(
                "Verifying command alignment for '%s'...",
                in_toto.models.link.FILENAME_FORMAT.format(
                    step_name=step.name, keyid=keyid
                ),
            )

            command = link.command
            verify_command_alignment(command, expected_command)


def verify_match_rule(rule_data, artifacts_queue, source_artifacts, links):
    """
    <Purpose>
      Filters artifacts from artifact queue using rule pattern and optional rule
      source prefix and consumes them if there is a corresponding destination
      artifact, filtered using the same rule pattern and an optional rule
      destination prefix, and source and destination artifacts have matching
      hashes.

      NOTE: The destination artifacts are extracted from the links dictionary,
      using destination name and destination type from the rule data. The source
      artifacts could also be extracted from the links dictionary, but would
      require the caller to pass source name and source type, as those are not
      encoded in the rule. However, we choose to let the caller directly pass the
      relevant artifacts.


    <Arguments>
      rule_data:
              An unpacked "MATCH" rule (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).


      source_artifacts:
              All artifacts of the source item (including hashes).

      links:
              A dictionary containing link metadata per step or inspection, e.g.:
              {
                <link name> : <Link object>,
                ...
              }

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    consumed = set()

    # The rule can only consume artifacts if the destination link exists
    dest_link = links.get(rule_data["dest_name"])
    if not dest_link:
        return consumed

    # Extract destination artifacts from destination link
    dest_artifacts = getattr(dest_link, rule_data["dest_type"])

    # Filter part 1 - Filter artifacts using optional source prefix, and subtract
    # prefix before filtering with rule pattern (see filter part 2) to prevent
    # globbing in the prefix.
    if rule_data["source_prefix"]:
        filtered_source_paths = []
        # Add trailing slash to source prefix if it does not exist
        normalized_source_prefix = os.path.join(
            rule_data["source_prefix"], ""
        ).replace("\\", "/")

        for artifact_path in artifacts_queue:
            if artifact_path.startswith(normalized_source_prefix):
                filtered_source_paths.append(
                    artifact_path[len(normalized_source_prefix) :]
                )

    else:
        filtered_source_paths = artifacts_queue

    # Filter part 2 - glob above filtered artifact paths
    filtered_source_paths = fnmatch.filter(
        filtered_source_paths, rule_data["pattern"]
    )

    # Iterate over filtered source paths and try to match the corresponding
    # source artifact hash with the corresponding destination artifact hash
    for path in filtered_source_paths:
        # If a source prefix was specified, we subtracted the prefix above before
        # globbing. We have to re-prepend the prefix in order to retrieve the
        # corresponding source artifact below.
        if rule_data["source_prefix"]:
            full_source_path = os.path.join(
                rule_data["source_prefix"], path
            ).replace("\\", "/")

        else:
            full_source_path = path

        # If a destination prefix was specified, the destination artifact should
        # be queried with the full destination path, i.e. the prefix joined with
        # the globbed path.
        if rule_data["dest_prefix"]:
            full_dest_path = os.path.join(
                rule_data["dest_prefix"], path
            ).replace("\\", "/")

        else:
            full_dest_path = path

        # Extract source artifact hash dict
        # We know the source artifact is available, it is also in the queue
        source_artifact = source_artifacts[full_source_path]

        # Don't consume source artifact w/o corresponding dest artifact (by path)
        try:
            dest_artifact = dest_artifacts[full_dest_path]
        except KeyError:
            continue

        # Don't consume source artifact w/o corresponding dest artifact (by hash)
        if source_artifact != dest_artifact:
            continue

        # Source and destination matched, consume artifact
        consumed.add(full_source_path)

    return consumed


def verify_create_rule(rule_pattern, artifacts_queue, materials, products):
    """
    <Purpose>
      Filters artifacts from artifacts queue using rule pattern and consumes them
      if they are not in the materials set but are in the products set, i.e.
      were created.

    <Arguments>
      rule_pattern:
              A "CREATE" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

      materials:
              All materials of an item (paths only).

      products:
              All products of an item (paths only).

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    # Filter queued artifacts using the rule pattern
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    # Consume filtered artifacts that are products but not materials
    consumed = set(filtered_artifacts) & (products - materials)

    return consumed


def verify_delete_rule(rule_pattern, artifacts_queue, materials, products):
    """
    <Purpose>
      Filters artifacts from artifacts queue using rule pattern and consumes them
      if they are in the materials set but are not in the products set, i.e.
      were deleted.

    <Arguments>
      rule_pattern:
              A "DELETE" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

      materials:
              All materials of an item (paths only).

      products:
              All products of an item (paths only).

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    # Filter queued artifacts using the rule pattern
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    # Consume filtered artifacts that are materials but not products
    consumed = set(filtered_artifacts) & (materials - products)

    return consumed


def verify_modify_rule(rule_pattern, artifacts_queue, materials, products):
    """
    <Purpose>
      Filters artifacts from artifacts queue using rule pattern and consumes them
      if they are in both the materials dict and in the products doct, but have
      different hashes, i.e. were modified.

    <Arguments>
      rule_pattern:
              A "MODIFY" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

      materials:
              All materials of an item (including hashes).

      products:
              All products of an item (including hashes).

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    # Filter queued artifacts using the rule pattern
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    # Filter filtered artifacts that are materials and products
    filtered_artifacts = (
        set(filtered_artifacts) & set(materials.keys()) & set(products.keys())
    )

    # Consume filtered artifacts that have different hashes
    consumed = set()
    for path in filtered_artifacts:
        if materials[path] != products[path]:
            consumed.add(path)

    return consumed


def verify_allow_rule(rule_pattern, artifacts_queue):
    """
    <Purpose>
      Consumes artifacts, filtered from the artifacts queue using rule pattern.

    <Arguments>
      rule_pattern:
              An "ALLOW" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    # Filter queued artifacts using the rule pattern
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    # Consume all filtered artifacts
    return set(filtered_artifacts)


def verify_disallow_rule(rule_pattern, artifacts_queue):
    """
    <Purpose>
      Raises RuleVerificationError if rule pattern applies to any artifacts in
      the queue.

      NOTE: Each set of rules should have a terminal DISALLOW rule to make
      overall verification fail in case preceding rules did not consume all
      artifacts as intended.

    <Arguments>
      rule_pattern:
              A "DISALLOW" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

    <Exceptions>
      RuleVerificationError
          if the rule pattern filters artifacts in the artifact queue.

    <Side Effects>
      None.

    <Returns>
      None.

    """
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    if filtered_artifacts:
        raise RuleVerificationError(
            "'DISALLOW {}' matched the following "
            "artifacts: {}\n{}".format(
                rule_pattern, filtered_artifacts, _get_artifact_rule_traceback()
            )
        )


def verify_require_rule(filename, artifacts_queue):
    """
    <Purpose>
      Raises RuleVerificationError if the filename provided does not exist in the
      artifacts_queue

    <Arguments>
      filename:
              A single filename (see issues #193 and #152). We will ignore the
              artifact rule pattern because it's ambiguous and instead treat it
              as a literal file name.

      artifacts_queue:
              Not yet consumed artifacts (paths only).

    <Exceptions>
      RuleVerificationError:
        if the filename is not present in the artifacts queue

    <Side Effects>
      None.

    <Returns>
      None.

    """
    if filename not in artifacts_queue:
        raise RuleVerificationError(
            "'REQUIRE {filename}' did not find {filename} "
            "in: {queue}\n{traceback}".format(
                filename=filename,
                queue=artifacts_queue,
                traceback=_get_artifact_rule_traceback(),
            )
        )


def _get_artifact_rule_traceback():
    """Build and return string form global `RULE_TRACE` which may be used as
    error message for RuleVerificationError.

    """
    traceback_str = "Full trace for 'expected_{0}' of item '{1}':\n".format(
        RULE_TRACE["source_type"], RULE_TRACE["source_name"]
    )

    # Show all materials and products available in the beginning and
    # label the one that is used to generate a queue.
    for source_type in ["materials", "products"]:
        traceback_str += "Available {}{}:\n{}\n".format(
            source_type,
            [" (used for queue)", ""][RULE_TRACE["source_type"] != source_type],
            RULE_TRACE[source_type],
        )

    for trace_entry in RULE_TRACE["trace"]:
        traceback_str += "Queue after '{0}':\n".format(
            " ".join(trace_entry["rule"])
        )
        traceback_str += "{}\n".format(trace_entry["queue"])

    return traceback_str


def verify_item_rules(source_name, source_type, rules, links):
    """
    <Purpose>
      Apply all passed material or product rules (see source_type) of a given
      step or inspection (see source_name), to enforce and authorize the
      corresponding artifacts and to guarantee that artifacts are linked together
      across steps of the supply chain.

      The mode of operation is similar to that of a firewall:
      In the beginning all materials or products of the step or inspection are
      placed into an artifact queue. The rules are then applied sequentially,
      consuming artifacts in the queue, i.e. removing them from the queue upon
      successful application.

      The consumption of artifacts by itself has no effects on the verification.
      Only through a subsequent "DISALLOW" rule, that finds unconsumed artifacts,
      is an exception raised. Similarly does the "REQUIRE" rule raise exception,
      if it does not find the artifact it requires, because it has falsely been
      consumed or was not there from the beginning.



    <Arguments>
      source_name:
              The name of the item (step or inspection) being verified.

      source_type:
              One of "materials" or "products" depending on whether the rules are
              taken from the "expected_materials" or "expected_products" field of
              the item being verified.

      rules:
              The list of rules (material or product rules) for the item being
              verified.

      links:
              A dictionary containing link metadata per step or inspection, e.g.:
              {
                <link name> : <Link object>,
                ...
              }

    <Exceptions>
      FormatError
          if source_type is not "materials" or "products", or
          if a rule in the passed list of rules does not conform with any rule
          format.

      RuleVerificationError
          if a DISALLOW rule matches disallowed artifacts, or
          if a REQUIRE rule does not find a required artifact.

    <Side Effects>
      Clears and populates the global RULE_TRACE data structure.

    """
    if source_type not in ["materials", "products"]:
        raise securesystemslib.exceptions.FormatError(
            "Argument 'source_type' of function 'verify_item_rules' has to be "
            "one of 'materials' or 'products'. Got: '{}'".format(source_type)
        )

    # Create shortcuts to item's materials and products (including hashes),
    # required to verify "modify" and "match" rules.
    materials_dict = links[source_name].materials
    products_dict = links[source_name].products

    # All other rules only require materials or products paths (without hashes)
    materials_paths = set(materials_dict.keys())
    products_paths = set(products_dict.keys())

    # Depending on the source type we create the artifact queue from the item's
    # materials or products and use it to keep track of (not) consumed artifacts.
    # The queue also only contains aritfact keys (without hashes)
    artifacts = getattr(links[source_name], source_type)
    artifacts_queue = set(artifacts.keys())

    # Reset and re-populate rule traceback info dict for a rich error message
    RULE_TRACE.clear()
    RULE_TRACE["source_name"] = source_name
    RULE_TRACE["source_type"] = source_type
    RULE_TRACE["materials"] = list(materials_dict)
    RULE_TRACE["products"] = list(products_dict)
    RULE_TRACE["trace"] = []

    # Process rules and remove consumed items from queue in each iteration
    for rule in rules:
        LOG.info("Verifying '%s'...", " ".join(rule))

        # Parse the rule and create two shortcuts to contained rule data
        rule_data = in_toto.rulelib.unpack_rule(rule)
        _type = rule_data["rule_type"]
        pattern = rule_data["pattern"]

        # Initialize empty consumed set as fallback for rules that do not consume
        # artifacts. All rules except "disallow" and "require" consume artifacts.
        consumed = set()

        if _type == "match":
            consumed = verify_match_rule(
                rule_data, artifacts_queue, artifacts, links
            )

        elif _type == "create":
            consumed = verify_create_rule(
                pattern, artifacts_queue, materials_paths, products_paths
            )

        elif _type == "delete":
            consumed = verify_delete_rule(
                pattern, artifacts_queue, materials_paths, products_paths
            )

        elif _type == "modify":
            consumed = verify_modify_rule(
                pattern, artifacts_queue, materials_dict, products_dict
            )

        elif _type == "allow":
            consumed = verify_allow_rule(pattern, artifacts_queue)

        # It's up to the "disallow" and "require" rule to raise an error if
        # artifacts were not consumed as intended
        elif _type == "disallow":
            verify_disallow_rule(pattern, artifacts_queue)

        elif _type == "require":
            verify_require_rule(pattern, artifacts_queue)

        else:  # pragma: no cover (unreachable)
            raise securesystemslib.exceptions.FormatError(
                "Invaldid rule type '{}'.".format(_type)
            )

        artifacts_queue -= consumed

        # Append rule and copy of queue to global info for a rich error message
        RULE_TRACE["trace"].append(
            {"rule": rule, "queue": list(artifacts_queue)}
        )


def verify_all_item_rules(items, links):
    """
    <Purpose>
      Iteratively verifies artifact rules of passed items (Steps or Inspections).

    <Arguments>
      items:
              A list containing Step or Inspection objects whose material
              and product rules will be verified.

      links:
              A dictionary containing link metadata per step or inspection, e.g.:
              {
                <link name> : <Link object>,
                ...
              }

    <Exceptions>
      None.

    <Side Effects>
      None.

    """
    for item in items:
        LOG.info("Verifying material rules for '%s'...", item.name)
        verify_item_rules(
            item.name, "materials", item.expected_materials, links
        )

        LOG.info("Verifying product rules for '%s'...", item.name)
        verify_item_rules(item.name, "products", item.expected_products, links)


def verify_threshold_constraints(layout, chain_link_dict):
    """
    <Purpose>
      Verifies that all links corresponding to a given step report the same
      materials and products.

      NOTE: This function does not verify if the signatures of each link
      corresponding to a step are valid or created by a different authorized
      functionary. This should be done earlier, using the function
      `verify_link_signature_thresholds`.

    <Arguments>
      layout:
              The layout whose step thresholds are being verified

      chain_link_dict:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Link object>,
                  ...
                }, ...
              }

    <Exceptions>
      ThresholdVerificationError
          If there are not enough (threshold) links for a steps

          If the artifacts for all links of a step are not equal


    <Side Effects>
      None.

    """

    # We are only interested in links that are related to steps defined in the
    # Layout, so iterate over layout.steps
    for step in layout.steps:
        # Skip steps that don't require multiple functionaries
        if step.threshold <= 1:
            LOG.info(
                "Skipping threshold verification for step '%s' with"
                " threshold '%s'...",
                step.name,
                step.threshold,
            )
            continue

        LOG.info(
            "Verifying threshold for step '%s' with threshold '%s'...",
            step.name,
            step.threshold,
        )
        # Extract the key_link_dict for this step from the passed chain_link_dict
        key_link_dict = chain_link_dict[step.name]

        # Check if we have at least <threshold> links for this step
        # NOTE: This is already done in `verify_link_signature_thresholds`,
        # Should we remove the check?
        if len(key_link_dict) < step.threshold:
            raise ThresholdVerificationError(
                "Step '{0}' not performed"
                " by enough functionaries!".format(step.name)
            )

        # Take a reference link (e.g. the first in the step_link_dict)
        reference_keyid = list(key_link_dict.keys())[0]
        reference_link = key_link_dict[reference_keyid]

        # Iterate over all links to compare their properties with a reference_link
        for keyid, link in key_link_dict.items():
            # TODO: Do we only care for artifacts, or do we want to
            # assert equality of other properties as well?
            if (
                reference_link.materials != link.materials
                or reference_link.products != link.products
            ):
                raise ThresholdVerificationError(
                    "Links '{0}' and '{1}' have different"
                    " artifacts!".format(
                        in_toto.models.link.FILENAME_FORMAT.format(
                            step_name=step.name, keyid=reference_keyid
                        ),
                        in_toto.models.link.FILENAME_FORMAT.format(
                            step_name=step.name, keyid=keyid
                        ),
                    )
                )


def reduce_chain_links(chain_link_dict):
    """
    <Purpose>
      Iterates through the passed chain_link_dict and builds a dict with
      step-name as keys and link objects as values.
      We already check if the links of different functionaries are
      identical.

    <Arguments>
      layout:
              The layout specified by the project owner against which the
              threshold will be verified.

      chain_link_dict:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Link object>,
                  ...
                }, ...
              }

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      A dictionary containing one Link metadata object per step only if
      the link artifacts of all link objects are identical for a step.

    """

    reduced_chain_link_dict = {}

    for step_name, key_link_dict in chain_link_dict.items():
        # Extract the key_link_dict for this step from the passed chain_link_dict
        # take one exemplary link (e.g. the first in the step_link_dict)
        # form the reduced_chain_link_dict to return
        reduced_chain_link_dict[step_name] = list(key_link_dict.values())[0]

    return reduced_chain_link_dict


def verify_sublayouts(
    layout, steps_metadata, superlayout_link_dir_path, inspect_timeout
):
    """
    <Purpose>
      Extracts link or layout object for each step in steps_metadata. Checks if
      any step has been delegated by the functionary, recurses into the
      delegation, and replaces the layout object with an equivalent link object.
      Returns the extracted link objects in a dict called chain_link_dict.

    <Arguments>
      layout:
              The layout specified by the project owner.

      steps_metadata:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Metadata containing a Link or Layout
                                            object>,
                  ...
                }, ...
              }

      superlayout_link_dir_path:
              A path to a directory, where links of the superlayout are loaded
              from. Links of the sublayout are expected to be in a subdirectory
              relative to this path, with a name in the format
              in_toto.models.layout.SUBLAYOUT_LINK_DIR_FORMAT.

      inspect_timeout:
              Integer value that is the number of seconds to pass to the run
              command to timeout the subprocess within.

    <Exceptions>
      raises an Exception if verification of the delegated step fails.

    <Side Effects>
      None.

    <Returns>
      The passed dictionary containing Link objects instead of metadata per
      functionary per step, with layouts replaced with summary links.
      e.g.:
      {
        <link name> : {
          <functionary key id> : <Link object>,
          ...
        }, ...
      }

    """
    chain_link_dict = {}

    for step_name, metadata_dict in steps_metadata.items():
        key_link_dict = {}
        for keyid, metadata in metadata_dict.items():
            payload = metadata.get_payload()

            if payload.type_ == "layout":
                LOG.info("Verifying sublayout %s...", step_name)
                layout_key_dict = {}

                # Retrieve the entire key object for the keyid
                # corresponding to the link
                layout_key_dict = {keyid: layout.keys.get(keyid)}

                # Sublayout links are expected to be in a directory with the following
                # name relative the the current link directory path, i.e. if there
                # are multiple levels of sublayout nesting, the links are expected to
                # be nested accordingly
                sub_link_dir = (
                    in_toto.models.layout.SUBLAYOUT_LINK_DIR_FORMAT.format(
                        name=step_name, keyid=keyid
                    )
                )

                sublayout_link_dir_path = os.path.join(
                    superlayout_link_dir_path, sub_link_dir
                )

                # Make a recursive call to in_toto_verify with the
                # layout and the extracted key object
                summary_link = in_toto_verify(
                    metadata,
                    layout_key_dict,
                    link_dir_path=sublayout_link_dir_path,
                    step_name=step_name,
                    inspect_timeout=inspect_timeout,
                )

                # Replace the layout object with the link object returned
                # by in-toto-verify
                payload = summary_link

            key_link_dict[keyid] = payload
        chain_link_dict[step_name] = key_link_dict

    return chain_link_dict


def get_summary_link(layout, reduced_chain_link_dict, name):
    """
    <Purpose>
      Merges the materials of the first step (as mentioned in the layout)
      and the products of the last step and returns a new link.
      This link reports the materials and products and summarizes the
      overall software supply chain.
      NOTE: The assumption is that the steps mentioned in the layout are
      to be performed sequentially. So, the first step mentioned in the
      layout denotes what comes into the supply chain and the last step
      denotes what goes out.

    <Arguments>
      layout:
              The layout specified by the project owner.

      reduced_chain_link_dict:
              A dictionary containing link metadata per step,
              e.g.:
              {
                <link name> : <Link object>,
                ...
              }
      name:
              The name that the summary link will be associated with.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      A Link object which summarizes the materials and products of the overall
      software supply chain.

    """
    # Create empty link object
    summary_link = in_toto.models.link.Link()

    # Take first and last link in the order the corresponding
    # steps appear in the layout, if there are any.
    if len(layout.steps) > 0:
        first_step_link = reduced_chain_link_dict[layout.steps[0].name]
        last_step_link = reduced_chain_link_dict[layout.steps[-1].name]

        summary_link.materials = first_step_link.materials
        summary_link.name = name

        summary_link.products = last_step_link.products
        summary_link.byproducts = last_step_link.byproducts
        summary_link.command = last_step_link.command

    return summary_link


def in_toto_verify(
    metadata,
    layout_key_dict,
    link_dir_path=".",
    substitution_parameters=None,
    step_name="",
    persist_inspection_links=True,
    inspect_timeout=in_toto.settings.LINK_CMD_EXEC_TIMEOUT,
):
    """Performs complete in-toto supply chain verification for a final product.

    The verification procedure consists of the following activities, performed in
    the given order:

    1.  Verify layout signatures
    2.  Verify layout expiration date
    3.  Substitute placeholders in the layout
    4.  Load link metadata
    5.  Verify link signatures with keys in layout
    6.  Recurse into sublayout verification
    7.  Soft-verify alignment of reported and expected commands. Note:
        verification does not fail if commands don't match, instead a warning is
        logged as per the in-toto specification --
        https://github.com/in-toto/docs/blob/master/in-toto-spec.md#431-steps
    8.  Verify threshold artifact constraints
    9.  Process step product and material rules
    10. Execute inspection commands and generate inspection links
    11. Process inspection product and material rules

    Note: in-toto's verification workflow directly uses the key for verifying
    signatures. It does not communicate with external sources of information for
    specific attributes about keys. This ensures that verification can be
    performed in isolation. It is the supply chain owner's responsibility to
    consider such attributes before using the key to sign the layout or adding
    it to the layout. For example, in-toto does not rely on the creation time,
    revocation status, and usage flags for PGP keys. To revoke or otherwise
    affect the usage of a key, the supply chain owner must sign a new layout
    with the corresponding changes.

    Arguments:
      metadata: A Metadata object that contains a Layout object to be verified.

      layout_key_dict: A public key dictionary. The verification routine requires
          at least one key, and a valid signature on the layout for each key.

      link_dir_path (optional): A directory path to link metadata files. The
          expected filename format for link metadata files is
          ``STEP-NAME.KEYID-PREFIX.link``. Link metadata files for a sublayout
          are loaded from a subdirectory relative to the link_dir_path of the
          superlayout. The expected directory name format is
          ``SUBLAYOUT-STEP-NAME.KEYID-PREFIX``.

      substitution_parameters (optional): A dictionary with substitution values
          for artifact rules (steps and inspections), the expected command
          attribute (steps), and the run attribute (inspections) in the layout.

      step_name (optional): A name assigned to the returned link. This is mostly
          useful during recursive sublayout verification.

      persist_inspection_links (optional): A boolean that determines whether or
          not link metadata files for inspection are written to cwd.

      inspect_timeout (optional): An integer value that defaults to
          in_toto.settings.LINK_CMD_EXEC_TIMEOUT in seconds which ends up timing
          out the run command subprocess if it runs over.

    Raises:
      securesystemslib.exceptions.FormatError: Passed parameters are malformed.

      SignatureVerificationError: No layout verification key is passed, or any of
          the passed keys fails to verify a signature.

      LayoutExpiredError: The layout is expired.

      LinkNotFoundError: Fewer than threshold link metadata files can be found
          for a step of the layout.

      ThresholdVerificationError: Fewer than threshold links, validly signed by
          different authorized functionaries, who agree on the recorded materials
          and products, can be found for a step of the layout. (Links with
          invalid signatures or signatures by unauthorized functionaries are
          ignored.)

      RuleVerificationError: A DISALLOW rule matches disallowed artifacts, or
          a REQUIRE rule does not find a required artifact.

      BadReturnValueError: An inspection command returns a non-zero value.

    Side Effects:
      Reads link metadata files from disk.
      Runs inspection commands in subprocess.

    Returns:
      A Link object, which summarizes the materials and products of the overall
      software supply chain. This is mostly useful during recursive sublayout
      verification.

    """

    LOG.info("Verifying layout metadata signatures...")
    verify_metadata_signatures(metadata, layout_key_dict)

    # For the rest of the verification we only care about the layout payload
    # (Layout) that carries all the information and not about the layout
    # container (Metablock) that also carries the signatures
    LOG.info("Extracting layout from metadata...")
    layout = metadata.get_payload()

    LOG.info("Verifying layout expiration...")
    verify_layout_expiration(layout)

    # If there are parameters sent to the translation layer, substitute them
    if substitution_parameters is not None:
        LOG.info("Performing parameter substitution...")
        substitute_parameters(layout, substitution_parameters)

    LOG.info("Reading link metadata files...")
    steps_metadata = load_links_for_layout(layout, link_dir_path)

    LOG.info("Verifying link metadata signatures...")
    steps_metadata = verify_link_signature_thresholds(layout, steps_metadata)

    LOG.info("Verifying sublayouts...")
    chain_link_dict = verify_sublayouts(
        layout, steps_metadata, link_dir_path, inspect_timeout
    )

    LOG.info("Verifying alignment of reported commands...")
    verify_all_steps_command_alignment(layout, chain_link_dict)

    LOG.info("Verifying threshold constraints...")
    verify_threshold_constraints(layout, chain_link_dict)
    reduced_chain_link_dict = reduce_chain_links(chain_link_dict)

    # NOTE: Processing step rules before executing inspections guarantees that
    # inspection commands don't run on compromised target files, however, this
    # also precludes step match rules from referencing inspection artifacts.
    LOG.info("Verifying Step rules...")
    verify_all_item_rules(layout.steps, reduced_chain_link_dict)

    LOG.info("Executing Inspection commands...")
    inspection_link_dict = run_all_inspections(
        layout, persist_inspection_links, inspect_timeout
    )

    LOG.info("Verifying Inspection rules...")
    # Artifact rules for inspections can reference links that correspond to
    # Steps or Inspections, hence the concatenation of both collections of links
    combined_links = reduced_chain_link_dict.copy()
    combined_links.update(inspection_link_dict)
    verify_all_item_rules(layout.inspect, combined_links)

    # We made it this far without exception that means, verification passed
    LOG.info("The software product passed all verification.")

    # Return a link file which summarizes the entire software supply chain
    # This is mostly relevant if the currently verified supply chain is embedded
    # in another supply chain
    return get_summary_link(layout, reduced_chain_link_dict, step_name)
