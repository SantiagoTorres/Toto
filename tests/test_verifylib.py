#!/usr/bin/env python

# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_verifylib.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  Nov 07, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test verifylib functions.

"""
# pylint: disable=protected-access

import copy
import glob
import os
import shlex
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import securesystemslib._gpg.functions
import securesystemslib.exceptions
from dateutil.relativedelta import relativedelta
from securesystemslib._gpg.constants import have_gpg
from securesystemslib._gpg.exceptions import KeyExpirationError

import in_toto.exceptions
import in_toto.settings
from in_toto.exceptions import (
    BadReturnValueError,
    LayoutExpiredError,
    RuleVerificationError,
    SignatureVerificationError,
    ThresholdVerificationError,
)
from in_toto.models.layout import (
    SUBLAYOUT_LINK_DIR_FORMAT,
    Inspection,
    Layout,
    Step,
)
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock
from in_toto.rulelib import unpack_rule
from in_toto.verifylib import (
    _raise_on_bad_retval,
    get_summary_link,
    in_toto_verify,
    load_links_for_layout,
    run_all_inspections,
    verify_all_item_rules,
    verify_allow_rule,
    verify_command_alignment,
    verify_create_rule,
    verify_delete_rule,
    verify_disallow_rule,
    verify_item_rules,
    verify_link_signature_thresholds,
    verify_match_rule,
    verify_modify_rule,
    verify_require_rule,
    verify_sublayouts,
    verify_threshold_constraints,
)
from tests.common import GPGKeysMixin, SignerStore, TmpDirMixin


class TestRaiseOnBadRetval(unittest.TestCase):
    """Tests internal function that raises an exception if the passed
    "return_value" is not and integer and not zero."""

    def test_zero_return_value(self):
        """Don't raise exception on zero return value."""
        _raise_on_bad_retval(0)
        _raise_on_bad_retval(0, "command")

    def test_non_int_return_value(self):
        """Raise exception on non-int return value."""
        with self.assertRaises(BadReturnValueError):
            _raise_on_bad_retval("bad retval")
        with self.assertRaises(BadReturnValueError):
            _raise_on_bad_retval("bad retval", "bad command")

    def test_non_zero_return_value(self):
        """Raise exception on non-zero return value."""
        with self.assertRaises(BadReturnValueError):
            _raise_on_bad_retval(1)
        with self.assertRaises(BadReturnValueError):
            _raise_on_bad_retval(-1, "bad command")


class TestRunAllInspections(unittest.TestCase, TmpDirMixin):
    """Test verifylib.run_all_inspections(layout, persist_inspection_links)"""

    @classmethod
    def setUpClass(cls):
        """
        Create layout with dummy inpsection.
        Create and change into temp test directory with dummy artifact."""

        # find where the scripts directory is located.
        scripts_directory = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "scripts"
        )

        # Create layout with one inspection
        cls.layout = Layout.read(
            {
                "_type": "layout",
                "steps": [],
                "inspect": [
                    {
                        "name": "touch-bar",
                        "run": [
                            "python",
                            os.path.join(scripts_directory, "touch"),
                            "bar",
                        ],
                    }
                ],
            }
        )

        # Create directory where the verification will take place
        cls.set_up_test_dir()
        with open("foo", "w", encoding="utf8") as f:
            f.write("foo")

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def test_inpsection_artifacts_with_base_path_ignored(self):
        """Create new dummy test dir and set as base path, must ignore."""
        ignore_dir = os.path.realpath(tempfile.mkdtemp())
        ignore_foo = os.path.join(ignore_dir, "ignore_foo")
        with open(ignore_foo, "w", encoding="utf8") as f:
            f.write("ignore foo")
        in_toto.settings.ARTIFACT_BASE_PATH = ignore_dir

        run_all_inspections(self.layout, True)
        link = Metablock.load("touch-bar.link")
        self.assertListEqual(list(link.signed.materials.keys()), ["foo"])
        self.assertListEqual(
            sorted(list(link.signed.products.keys())), sorted(["foo", "bar"])
        )

        in_toto.settings.ARTIFACT_BASE_PATH = None
        shutil.rmtree(ignore_dir)

    def test_inspection_fail_with_non_zero_retval(self):
        """Test fail run inspections with non-zero return value."""
        layout = Layout.read(
            {
                "_type": "layout",
                "steps": [],
                "inspect": [
                    {
                        "name": "non-zero-inspection",
                        "run": ["python", "./scripts/expr", "1", "/", "0"],
                    }
                ],
            }
        )
        with self.assertRaises(BadReturnValueError):
            run_all_inspections(layout, True)

    def test_inspection_persistence_false(self):
        """Test metadata link file non-persistence"""
        if os.path.exists("touch-bar.link"):
            os.remove("touch-bar.link")
        run_all_inspections(self.layout, False)
        self.assertFalse(os.path.exists("touch-bar.link"))

    def test_inspeciton_persistence_true(self):
        run_all_inspections(self.layout, True)
        self.assertTrue(os.path.exists("touch-bar.link"))


class TestVerifyCommandAlignment(unittest.TestCase):
    """Test verifylib.verify_command_alignment(command, expected_command)"""

    def setUp(self):
        self.command = ["vi", "file1", "file2"]

    def test_commands_align(self):
        """Cmd and expected cmd are equal, passes."""
        expected_command = ["vi", "file1", "file2"]
        verify_command_alignment(self.command, expected_command)

    def test_commands_do_not_fully_align_log_warning(self):
        """Cmd and expected cmd differ slightly."""
        expected_command = ["/usr/bin/vi", "file1", "file2"]

        with patch("in_toto.verifylib.LOG") as mock_logging:
            verify_command_alignment(self.command, expected_command)
            mock_logging.warning.assert_called_with(
                "Run command '%s' differs from expected command '%s'",
                self.command,
                expected_command,
            )

    def test_commands_do_not_align_at_all_log_warning(self):
        """Cmd and expected cmd differ completely."""
        expected_command = ["make install"]

        with patch("in_toto.verifylib.LOG") as mock_logging:
            verify_command_alignment(self.command, expected_command)
            mock_logging.warning.assert_called_with(
                "Run command '%s' differs from expected command '%s'",
                self.command,
                expected_command,
            )
    
    def test_commands_align_with_regex_1(self):
        command = ["/usr/bin/vi", "file1", "file2"]
        regex = True
        expected_command = "(/usr/bin/)?vi file1 file2"
        verify_command_alignment(command, expected_command, regex=regex)
    
    def test_commands_align_with_regex_2(self):
        command = ["vi", "file1", "file2"]
        regex = True
        expected_command = "(/usr/bin/)?vi file1 file2"
        verify_command_alignment(command, expected_command, regex=regex)

    def test_commands_do_not_align_with_regex(self):
        command = ["/usr/bin/diff", "file1", "file2"]
        regex = True
        expected_command = "(/usr/bin/)?vi file1 file2"
        with patch("in_toto.verifylib.LOG") as mock_logging:
            verify_command_alignment(command, expected_command, regex=regex)
            mock_logging.warning.assert_called_with(
                    "Run command '%s' differs from expected regex '%s'",
                    command,
                    expected_command,
                )
        


class TestVerifyRule(unittest.TestCase):
    """Table driven tests for individual rule verification functions."""

    def test_verify_delete_rule(self):
        """Test verifylib.verify_delete_rule."""
        test_data_keys = [
            "rule pattern",
            "artifact queue",
            "materials",
            "products",
            "expected",
        ]
        test_cases = [
            # Consume deleted artifact
            ["foo", {"foo"}, {"foo"}, set(), {"foo"}],
            # Consume multiple deleted artifacts with wildcard
            ["*", {"foo", "bar"}, {"foo", "bar"}, set(), {"foo", "bar"}],
            # Don't consume created artifact (in products only)
            ["foo", {"foo"}, set(), {"foo"}, set()],
            # Don't consume artifact that's not in materials or products
            # NOTE: In real life this shouldn't be in the queue either
            ["foo", {"foo"}, set(), set(), set()],
            # Don't consume deleted but not queued artifact
            ["foo", set(), {"foo"}, set(), set()],
            # Don't consume deleted but not matched artifact
            ["bar", {"foo"}, {"foo"}, set(), set()],
        ]

        for i, test_data in enumerate(test_cases):
            pattern, queue, materials, products, expected = test_data
            result = verify_delete_rule(pattern, queue, materials, products)
            self.assertSetEqual(
                result,
                expected,
                "test {}: {}".format(i, dict(zip(test_data_keys, test_data))),
            )

    def test_verify_create_rule(self):
        """Test verifylib.verify_create_rule."""
        test_data_keys = [
            "rule pattern",
            "artifact queue",
            "materials",
            "products",
            "expected",
        ]
        test_cases = [
            # Consume created artifact
            ["foo", {"foo"}, set(), {"foo"}, {"foo"}],
            # Consume multiple created artifacts with wildcard
            ["*", {"foo", "bar"}, set(), {"foo", "bar"}, {"foo", "bar"}],
            # Don't consume deleted artifact (in materials only)
            ["foo", {"foo"}, {"foo"}, set(), set()],
            # Don't consume artifact that's not in materials or products
            # NOTE: In real life this shouldn't be in the queue either
            ["foo", {"foo"}, set(), set(), set()],
            # Don't consume created but not queued artifact
            ["foo", set(), set(), {"foo"}, set()],
            # Don't consume created but not matched artifact
            ["bar", {"foo"}, set(), {"foo"}, set()],
        ]

        for i, test_data in enumerate(test_cases):
            pattern, queue, materials, products, expected = test_data
            result = verify_create_rule(pattern, queue, materials, products)
            self.assertSetEqual(
                result,
                expected,
                "test {}: {}".format(i, dict(zip(test_data_keys, test_data))),
            )

    def test_verify_modify_rule(self):
        """Test verifylib.verify_modify_rule."""
        sha_a = (
            "d65165279105ca6773180500688df4bdc69a2c7b771752f0a46ef120b7fd8ec3"
        )
        sha_b = (
            "155c693a6b7481f48626ebfc545f05236df679f0099225d6d0bc472e6dd21155"
        )

        test_data_keys = [
            "rule pattern",
            "artifact queue",
            "materials",
            "products",
            "expected",
        ]
        test_cases = [
            # Consume modified artifact
            [
                "foo",
                {"foo"},
                {"foo": {"sha256": sha_a}},
                {"foo": {"sha256": sha_b}},
                {"foo"},
            ],
            # Consume multiple modified artifacts with wildcard
            [
                "*",
                {"foo", "bar"},
                {"foo": {"sha256": sha_a}, "bar": {"sha256": sha_a}},
                {"foo": {"sha256": sha_b}, "bar": {"sha256": sha_b}},
                {"foo", "bar"},
            ],
            # Don't consume unmodified artifact
            [
                "foo",
                {"foo"},
                {"foo": {"sha256": sha_a}},
                {"foo": {"sha256": sha_a}},
                set(),
            ],
            # Don't consume artifact that's not in materials or products
            # NOTE: In real life this shouldn't be in the queue either
            ["foo", {"foo"}, {}, {}, set()],
            # Don't consume modified but not queued artifact
            [
                "foo",
                set(),
                {"foo": {"sha256": sha_a}},
                {"foo": {"sha256": sha_b}},
                set(),
            ],
            # Don't consume modified but not matched artifact
            [
                "bar",
                {"foo"},
                {"foo": {"sha256": sha_a}},
                {"foo": {"sha256": sha_b}},
                set(),
            ],
        ]

        for i, test_data in enumerate(test_cases):
            pattern, queue, materials, products, expected = test_data
            result = verify_modify_rule(pattern, queue, materials, products)
            self.assertSetEqual(
                result,
                expected,
                "test {}: {}".format(i, dict(zip(test_data_keys, test_data))),
            )

    def test_verify_allow_rule(self):
        """Test verifylib.verify_allow_rule."""
        test_data_keys = ["rule pattern", "artifact queue", "expected"]
        test_cases = [
            # Consume allowed artifact
            ["foo", {"foo"}, {"foo"}],
            # Consume multiple allowed artifacts with wildcard
            ["*", {"foo", "bar"}, {"foo", "bar"}],
            # Consume multiple allowed artifacts with wildcard 2
            ["foo*", {"foo", "foobar", "bar"}, {"foo", "foobar"}],
            # Don't consume unmatched artifacts
            ["bar", {"foo"}, set()],
            # Don't consume artifacts if nothing is in the queue
            ["foo", set(), set()],
        ]
        for i, test_data in enumerate(test_cases):
            pattern, queue, expected = test_data
            result = verify_allow_rule(pattern, queue)
            self.assertSetEqual(
                result,
                expected,
                "test {}: {}".format(i, dict(zip(test_data_keys, test_data))),
            )

    def test_verify_disallow_rule(self):
        """Test verifylib.verify_disallow_rule."""
        test_data_keys = ["rule pattern", "artifact queue"]
        test_cases = [
            # Foo disallowed, raise
            ["foo", {"foo"}, True],
            # All disallowed, raise
            ["*", {"foo", "bar"}, True],
            # Foo disallowed, but only bar there, don't raise
            ["foo", {"bar"}, False],
            # All disallowed, but no artifacts, don't raise
            ["*", {}, False],
        ]

        for i, test_data in enumerate(test_cases):
            pattern, queue, should_raise = test_data

            msg = "test {}: {}".format(i, dict(zip(test_data_keys, test_data)))
            exception = None

            try:
                verify_disallow_rule(pattern, queue)
            except RuleVerificationError as e:
                exception = e

            if should_raise and not exception:
                self.fail("Expected 'RuleVerificationError'\n{}".format(msg))

            if exception and not should_raise:
                self.fail("Unexpected {}\n{}".format(exception, msg))

    def test_verify_require_rule(self):
        """Test verifylib.verify_require_rule."""
        test_data_keys = ["rule pattern", "artifact queue"]
        test_cases = [
            # Foo required, pass
            ["foo", {"foo"}, False],
            # Foo is required, but only bar there, blow up
            ["foo", {"bar"}, True],
            # A pattern is passed, which should be interpreted *literally*
            ["*", {"*"}, False],
            ["*", {"foo"}, True],
            #
        ]

        for i, test_data in enumerate(test_cases):
            pattern, queue, should_raise = test_data

            msg = "test {}: {}".format(i, dict(zip(test_data_keys, test_data)))
            exception = None

            try:
                verify_require_rule(pattern, queue)
            except RuleVerificationError as e:
                exception = e

            if should_raise and not exception:
                self.fail("Expected 'RuleVerificationError'\n{}".format(msg))

            if exception and not should_raise:
                self.fail("Unexpected {}\n{}".format(exception, msg))


class TestVerifyMatchRule(unittest.TestCase):
    """Test verifylib.verify_match_rule(rule, artifact_queue, artifacts, links)"""

    def setUp(self):
        """Setup artifact queues, artifacts dictionary and Link dictionary."""

        # Dummy artifact hashes
        self.sha256_foo = (
            "d65165279105ca6773180500688df4bdc69a2c7b771752f0a46ef120b7fd8ec3"
        )
        self.sha256_foobar = (
            "155c693a6b7481f48626ebfc545f05236df679f0099225d6d0bc472e6dd21155"
        )
        self.sha256_bar = (
            "cfdaaf1ab2e4661952a9dec5e8fa3c360c1b06b1a073e8493a7c46d2af8c504b"
        )
        self.sha256_barfoo = (
            "2036784917e49b7685c7c17e03ddcae4a063979aa296ee5090b5bb8f8aeafc5d"
        )

        # Link dictionary containing dummy artifacts related to Steps the rule is
        # matched with (match destination).
        self.materials = {
            "foo": {"sha256": self.sha256_foo},
            "foobar": {"sha256": self.sha256_foobar},
            "sub/foo": {"sha256": self.sha256_foo},
            "sub/foobar": {"sha256": self.sha256_foobar},
            "lib/foo": {"sha256": self.sha256_foo},
            "lib/foobar": {"sha256": self.sha256_foobar},
            "lib/build/foo": {"sha256": self.sha256_foo},
            "lib/build/foobar": {"sha256": self.sha256_foobar},
        }
        self.products = {
            "bar": {"sha256": self.sha256_bar},
            "barfoo": {"sha256": self.sha256_barfoo},
            "sub/bar": {"sha256": self.sha256_bar},
            "sub/barfoo": {"sha256": self.sha256_barfoo},
            "sub/lib/bar": {"sha256": self.sha256_bar},
            "sub/lib/barfoo": {"sha256": self.sha256_barfoo},
            "build/bar": {"sha256": self.sha256_bar},
            "build/barfoo": {"sha256": self.sha256_barfoo},
        }

        self.links = {
            "dest-item": Link(
                name="dest-item",
                materials=self.materials,
                products=self.products,
            ),
        }

    def test_verify_match_rule(self):
        test_data_keys = [
            "rule string",
            "artifacts queue",
            "source artifacts",
            "expected",
        ]
        test_cases = [
            [
                # Consume foo matching with dest material foo
                "MATCH foo WITH MATERIALS FROM dest-item",
                set(self.materials.keys()),
                self.materials,
                {"foo"},
            ],
            [
                # Consume foo matching with dest product foo
                "MATCH bar WITH PRODUCTS FROM dest-item",
                set(self.products.keys()),
                self.products,
                {"bar"},
            ],
            [
                # Consume sub/foo matching with dest material foo
                "MATCH foo IN sub WITH MATERIALS FROM dest-item",
                set(self.materials.keys()),
                self.materials,
                {"sub/foo"},
            ],
            [
                # Consume sub/foo matching with dest material foo (ignore trailing /)
                "MATCH foo IN sub/ WITH MATERIALS FROM dest-item",
                set(self.materials.keys()),
                self.materials,
                {"sub/foo"},
            ],
            [
                # Consume sub/bar matching with dest product bar
                "MATCH bar IN sub WITH PRODUCTS FROM dest-item",
                set(self.products.keys()),
                self.products,
                {"sub/bar"},
            ],
            [
                # Consume foo matching with dest material sub/foo
                "MATCH foo WITH MATERIALS IN sub FROM dest-item",
                set(self.materials.keys()),
                self.materials,
                {"foo"},
            ],
            [
                # Consume bar matching with dest product sub/bar
                "MATCH bar WITH PRODUCTS IN sub FROM dest-item",
                set(self.products.keys()),
                self.products,
                {"bar"},
            ],
            [
                # Consume bar matching with dest product sub/bar (ignore trailing /)
                "MATCH bar WITH PRODUCTS IN sub/ FROM dest-item",
                set(self.products.keys()),
                self.products,
                {"bar"},
            ],
            [
                # Consume foo* matching with dest material foo*
                "MATCH foo* WITH MATERIALS FROM dest-item",
                set(self.materials.keys()),
                self.materials,
                {"foo", "foobar"},
            ],
            [
                # Consume sub/foo* matching with dest material foo*
                "MATCH foo* IN sub WITH MATERIALS FROM dest-item",
                set(self.materials.keys()),
                self.materials,
                {"sub/foo", "sub/foobar"},
            ],
            [
                # Consume bar* matching with dest product bar*
                "MATCH bar* WITH PRODUCTS FROM dest-item",
                set(self.products.keys()),
                self.products,
                {"bar", "barfoo"},
            ],
            [
                # Consume bar* matching with dest product sub/bar*
                "MATCH bar* WITH PRODUCTS IN sub FROM dest-item",
                set(self.products.keys()),
                self.products,
                {"bar", "barfoo"},
            ],
            [
                # Don't consume (empty queue)
                "MATCH foo WITH MATERIALS FROM dest-item",
                set(),
                self.materials,
                set(),
            ],
            [
                # Don't consume (no destination artifact)
                "MATCH foo WITH PRODUCTS FROM dest-item",
                set(self.materials.keys()),
                self.materials,
                set(),
            ],
            [
                # Don't consume (non-matching hashes)
                "MATCH foo WITH MATERIALS FROM dest-item",
                {"foo"},
                {"foo": {"sha256": "deadbeef"}},
                set(),
            ],
            [
                # Don't consume (missing link)
                "MATCH foo WITH MATERIALS FROM dest-item-missing-link",
                set(self.materials.keys()),
                self.materials,
                set(),
            ],
            [
                # Ensures the sub/bar file matches the product file in the sub folder
                # from the dest-item step.
                "MATCH bar IN sub WITH PRODUCTS IN sub FROM dest-item",
                set(self.products.keys()),
                self.products,
                {"sub/bar"},
            ],
            [
                # Ensures the sub/bar and sub/barfoo files matches the product
                # files in the sub folder from the dest-item step.
                "MATCH bar* IN sub WITH PRODUCTS IN sub/ FROM dest-item",
                set(self.products.keys()),
                self.products,
                {"sub/bar", "sub/barfoo"},
            ],
            [
                # Ensure the sub/bar file matches the product file in the
                # sub/lib folder from the dest-item step.
                "MATCH bar IN sub WITH PRODUCTS IN sub/lib FROM dest-item",
                set(self.products.keys()),
                self.products,
                {"sub/bar"},
            ],
            [
                # Do not consume. Missing link
                "MATCH bar IN sub WITH PRODUCTS IN sub FROM dest-item-missing-link",
                set(self.products.keys()),
                self.products,
                set(),
            ],
            [
                # Ensures the sub/foo file matches the material file in the
                # lib folder from the dest-item step.
                "MATCH foo IN sub WITH MATERIALS IN lib FROM dest-item",
                set(self.materials.keys()),
                self.materials,
                {"sub/foo"},
            ],
            [
                # Ensures any sub/foo and sub/foobar files matches material
                # files in the lib folder from the dest-item step.
                "MATCH foo* IN sub WITH MATERIALS IN lib/ FROM dest-item",
                set(self.materials.keys()),
                self.materials,
                {"sub/foo", "sub/foobar"},
            ],
            [
                # Ensures the sub/foo file matches the material files in the lib/build
                # the lib/build folder from the dest-item step.
                "MATCH foo IN sub WITH MATERIALS IN lib/build FROM dest-item",
                set(self.materials.keys()),
                self.materials,
                {"sub/foo"},
            ],
            [
                # Ensures the sub/foo and sub/foobar files matches the material files
                # in the lib/build folder from the dest-item step.
                "MATCH foo* IN sub WITH MATERIALS IN lib/build FROM dest-item",
                set(self.materials.keys()),
                self.materials,
                {"sub/foo", "sub/foobar"},
            ],
        ]

        for i, test_data in enumerate(test_cases):
            rule_string, queue, source_artifacts, expected = test_data

            # Generate rule data from rule string
            rule_data = unpack_rule(shlex.split(rule_string))

            result = verify_match_rule(
                rule_data, queue, source_artifacts, self.links
            )

            self.assertSetEqual(
                result,
                expected,
                "'result': {}\n test {}: {}, 'links':{}".format(
                    result, i, dict(zip(test_data_keys, test_data)), self.links
                ),
            )


class TestVerifyItemRules(unittest.TestCase):
    """Test verifylib.verify_item_rules(source_name, source_type, rules, links)"""

    def setUp(self):
        self.item_name = "item"
        self.sha256_1 = (
            "d65165279105ca6773180500688df4bdc69a2c7b771752f0a46ef120b7fd8ec3"
        )
        self.sha256_2 = (
            "cfdaaf1ab2e4661952a9dec5e8fa3c360c1b06b1a073e8493a7c46d2af8c504b"
        )

        self.links = {
            "item": Link(
                name="item",
                materials={
                    "foo": {"sha256": self.sha256_1},
                    "foobar": {"sha256": self.sha256_1},
                    "bar": {"sha256": self.sha256_1},
                    "foobarbaz": {"sha256": self.sha256_1},
                },
                products={
                    "baz": {"sha256": self.sha256_1},
                    "foo": {"sha256": self.sha256_1},
                    "bar": {"sha256": self.sha256_2},
                    "foobarbaz": {"sha256": self.sha256_1},
                },
            )
        }

    def test_pass_rules_with_each_rule_type(self):
        """Pass with list of rules of each rule type."""
        rules = [
            ["DELETE", "foobar"],
            ["REQUIRE", "foobarbaz"],
            ["CREATE", "baz"],
            ["MODIFY", "bar"],
            [
                "MATCH",
                "foo",
                "WITH",
                "MATERIALS",
                "FROM",
                "item",
            ],  # match with self
            ["ALLOW", "foobarbaz"],
            ["DISALLOW", "*"],
        ]
        for source_type in ["materials", "products"]:
            verify_item_rules(self.item_name, source_type, rules, self.links)

    def test_fail_disallow_not_consumed_artifacts(self):
        """Fail with not consumed artifacts and terminal DISALLOW."""
        rules = [
            ["DISALLOW", "*"],
        ]
        with self.assertRaises(RuleVerificationError):
            verify_item_rules(self.item_name, "materials", rules, self.links)

    def test_fail_wrong_source_type(self):
        """Fail with wrong source_type."""
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            verify_item_rules(self.item_name, "artifacts", [], self.links)

    def test_pass_not_consumed_artifacts(self):
        """Pass with not consumed artifacts and implicit terminal ALLOW *"""
        verify_item_rules(self.item_name, "materials", [], self.links)


class TestVerifyAllItemRules(unittest.TestCase):
    """Test verifylib.verify_all_item_rules(items, links)."""

    def setUp(self):
        """Create a dummy supply chain with two steps one inspection and the
        according link metadata:

        write-code (Step) ->  package (step) -> untar (Inspection)

        'write-code' creates an artifact foo
        'package' creates foo.tar.gz and deletes foo
        'untar' untars foo.tar.gz which results in foo.tar.gz and foo

        """

        self.sha256_foo = (
            "d65165279105ca6773180500688df4bdc69a2c7b771752f0a46ef120b7fd8ec3"
        )
        self.sha256_foo_tar = (
            "93c3c35a039a6a3d53e81c5dbee4ebb684de57b7c8be11b8739fd35804a0e918"
        )

        self.steps = [
            Step(
                name="write-code",
                expected_products=[["CREATE", "foo"]],
            ),
            Step(
                name="package",
                expected_materials=[
                    ["MATCH", "foo", "WITH", "PRODUCTS", "FROM", "write-code"]
                ],
                expected_products=[["CREATE", "foo.tar.gz"], ["DELETE", "foo"]],
            ),
        ]

        self.inspections = [
            Inspection(
                name="untar",
                expected_materials=[
                    ["REQUIRE", "foo.tar.gz"],
                    [
                        "MATCH",
                        "foo.tar.gz",
                        "WITH",
                        "PRODUCTS",
                        "FROM",
                        "package",
                    ],
                ],
                expected_products=[
                    [
                        "MATCH",
                        "foo",
                        "IN",
                        "dir",
                        "WITH",
                        "PRODUCTS",
                        "FROM",
                        "write-code",
                    ]
                ],
            )
        ]

        self.links = {
            "write-code": Link(
                name="write-code", products={"foo": {"sha256": self.sha256_foo}}
            ),
            "package": Link(
                name="package",
                materials={"foo": {"sha256": self.sha256_foo}},
                products={"foo.tar.gz": {"sha256": self.sha256_foo_tar}},
            ),
            "untar": Link(
                name="untar",
                materials={"foo.tar.gz": {"sha256": self.sha256_foo_tar}},
                products={
                    "dir/foo": {"sha256": self.sha256_foo},
                },
            ),
        }

    def test_pass_verify_all_step_rules(self):
        """Pass rule verification for dummy supply chain Steps."""
        verify_all_item_rules(self.steps, self.links)

    def test_pass_verify_all_inspection_rules(self):
        """Pass rule verification for dummy supply chain Inspections."""
        verify_all_item_rules(self.inspections, self.links)


class TestInTotoVerify(unittest.TestCase, TmpDirMixin):
    """
    Tests verifylib.in_toto_verify(layout_path, layout_key_paths).

    Uses in-toto demo supply chain link metadata files and basic layout for
    verification.

    Copies the basic layout for different test scenarios:
      - single-signed layout
      - double-signed layout
      - expired layout
      - layout with failing link rule
      - layout with failing step rule

    """

    @classmethod
    def setUpClass(cls):
        """Creates and changes into temporary directory.
        Copies demo files to temp dir...
          - owner/functionary key pairs
          - *.link metadata files
          - layout template (not signed, no expiration date)
          - final product

        ...and dumps various layouts for different test scenarios
        """
        # pylint: disable=too-many-statements

        # Find demo files
        demo_files = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "demo_files"
        )

        # find where the scripts directory is located.
        scripts_directory = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "scripts"
        )

        # Create and change into temporary directory
        cls.set_up_test_dir()

        # Copy demo files to temp dir
        for fn in os.listdir(demo_files):
            shutil.copy(os.path.join(demo_files, fn), cls.test_dir)

        # copy scripts over
        shutil.copytree(scripts_directory, "scripts")

        # Load layout template
        layout_template = Metablock.load("demo.layout.template")

        # Store various layout paths to be used in tests
        cls.layout_single_signed_path = "single-signed.layout"
        cls.layout_double_signed_path = "double-signed.layout"
        cls.layout_fixed_expiry_path = "fixed-datetime-expiry.layout"
        cls.layout_bad_sig = "bad-sig.layout"
        cls.layout_expired_path = "expired.layout"
        cls.layout_failing_step_rule_path = "failing-step-rule.layout"
        cls.layout_failing_inspection_rule_path = (
            "failing-inspection-rule.layout"
        )
        cls.layout_failing_inspection_retval = (
            "failing-inspection-retval.layout"
        )
        cls.layout_no_steps_no_inspections = "no_steps_no_inspections.layout"

        # Import layout signing keys
        alice = SignerStore.rsa
        bob = SignerStore.ecdsa

        cls.alice_pub = SignerStore.rsa_pub
        cls.bob_pub = SignerStore.ecdsa_pub

        # dump single signed layout
        layout = copy.deepcopy(layout_template)
        layout.create_signature(alice)
        layout.dump(cls.layout_single_signed_path)

        # dump double signed layout
        layout = copy.deepcopy(layout_template)
        layout.create_signature(alice)
        layout.create_signature(bob)
        layout.dump(cls.layout_double_signed_path)

        # dump layout with fixed (and mocked) date expiry
        layout = copy.deepcopy(layout_template)
        layout.signed.expires = (
            datetime(2025, 1, 2, 3, 4, 6, tzinfo=timezone.utc)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        layout.create_signature(alice)
        layout.dump(cls.layout_fixed_expiry_path)

        # dump layout with bad signature
        layout = copy.deepcopy(layout_template)
        layout.create_signature(alice)
        layout.signed.readme = "this breaks the signature"
        layout.dump(cls.layout_bad_sig)

        # dump expired layout
        layout = copy.deepcopy(layout_template)
        layout.signed.expires = (
            datetime.today() + relativedelta(months=-1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        layout.create_signature(alice)
        layout.dump(cls.layout_expired_path)

        # dump layout with failing step rule
        layout = copy.deepcopy(layout_template)
        layout.signed.steps[0].expected_products.insert(0, ["DISALLOW", "*"])
        layout.signed.steps[0].expected_products.insert(0, ["MODIFY", "*"])
        layout.create_signature(alice)
        layout.dump(cls.layout_failing_step_rule_path)

        # dump layout with failing inspection rule
        layout = copy.deepcopy(layout_template)
        layout.signed.inspect[0].expected_materials.insert(0, ["MODIFY", "*"])
        layout.signed.inspect[0].expected_materials.append(["DISALLOW", "*"])
        layout.create_signature(alice)
        layout.dump(cls.layout_failing_inspection_rule_path)

        # dump layout with failing inspection retval
        layout = copy.deepcopy(layout_template)
        layout.signed.inspect[0].run = [
            "python",
            "./scripts/expr",
            "1",
            "/",
            "0",
        ]
        layout.create_signature(alice)
        layout.dump(cls.layout_failing_inspection_retval)

        # dump empty layout
        layout = Metablock(signed=Layout())
        layout.create_signature(alice)
        layout.dump(cls.layout_no_steps_no_inspections)

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def test_verify_passing(self):
        """Test pass verification of single-signed layout."""
        layout = Metablock.load(self.layout_single_signed_path)
        layout_key_dict = {self.alice_pub["keyid"]: self.alice_pub}
        in_toto_verify(layout, layout_key_dict)

    def test_verify_passing_double_signed_layout(self):
        """Test pass verification of double-signed layout."""
        layout = Metablock.load(self.layout_double_signed_path)
        layout_key_dict = {
            self.alice_pub["keyid"]: self.alice_pub,
            self.bob_pub["keyid"]: self.bob_pub,
        }
        in_toto_verify(layout, layout_key_dict)

    def test_verify_passing_empty_layout(self):
        """Test pass verification of layout without steps or inspections."""
        layout = Metablock.load(self.layout_no_steps_no_inspections)
        layout_key_dict = {self.alice_pub["keyid"]: self.alice_pub}
        in_toto_verify(layout, layout_key_dict)

    def test_verify_passing_layout_expiry(self):
        """Test pass verification at expire < current timestamp."""
        with patch("""in_toto.verifylib.datetime""") as mock_date:
            mock_date.datetime.now.return_value = datetime(
                2025, 1, 2, 3, 4, 5, tzinfo=timezone.utc
            )
            layout = Metablock.load(self.layout_fixed_expiry_path)
            layout_key_dict = {self.alice_pub["keyid"]: self.alice_pub}
            # the expiry is a second later than the mocked datetime.datetime.now(), which
            # should not raise an exception due to <= behaviour of expiration comparison
            in_toto_verify(layout, layout_key_dict)

    def test_verify_failing_wrong_key(self):
        """Test fail verification with wrong layout key."""
        layout = Metablock.load(self.layout_single_signed_path)
        layout_key_dict = {self.bob_pub["keyid"]: self.bob_pub}
        with self.assertRaises(SignatureVerificationError):
            in_toto_verify(layout, layout_key_dict)

    def test_verify_failing_bad_signature(self):
        """Test fail verification with bad layout signature."""
        layout = Metablock.load(self.layout_bad_sig)
        layout_key_dict = {self.alice_pub["keyid"]: self.alice_pub}
        with self.assertRaises(SignatureVerificationError):
            in_toto_verify(layout, layout_key_dict)

    def test_verify_failing_layout_expired(self):
        """Test fail verification with expired layout."""
        layout = Metablock.load(self.layout_expired_path)
        layout_key_dict = {self.alice_pub["keyid"]: self.alice_pub}
        with self.assertRaises(LayoutExpiredError):
            in_toto_verify(layout, layout_key_dict)

    def test_verify_failing_layout_at_expire_timestamp(self):
        """Test fail expiry verification at current==expire timestamp."""
        with patch("""in_toto.verifylib.datetime""") as mock_date:
            mock_date.datetime.now.return_value = datetime(
                2025, 1, 2, 3, 4, 6, tzinfo=timezone.utc
            )
            layout = Metablock.load(self.layout_fixed_expiry_path)
            layout_key_dict = {self.alice_pub["keyid"]: self.alice_pub}
            # the expiry is the same as the mocked datetime.datetime.now(), which
            # should raise an exception due to <= behaviour of expiration comparison
            with self.assertRaises(LayoutExpiredError):
                in_toto_verify(layout, layout_key_dict)

    def test_verify_failing_link_metadata_files(self):
        """Test fail verification with link metadata files not found."""
        os.rename("package.2f89b927.link", "package.link.bak")
        layout = Metablock.load(self.layout_single_signed_path)
        layout_key_dict = {self.alice_pub["keyid"]: self.alice_pub}
        with self.assertRaises(in_toto.exceptions.LinkNotFoundError):
            in_toto_verify(layout, layout_key_dict)
        os.rename("package.link.bak", "package.2f89b927.link")

    def test_verify_failing_inspection_exits_non_zero(self):
        """Test fail verification with inspection returning non-zero."""
        layout = Metablock.load(self.layout_failing_inspection_retval)
        layout_key_dict = {self.alice_pub["keyid"]: self.alice_pub}
        with self.assertRaises(BadReturnValueError):
            in_toto_verify(layout, layout_key_dict)

    def test_verify_failing_step_rules(self):
        """Test fail verification with failing step artifact rule."""
        layout = Metablock.load(self.layout_failing_step_rule_path)
        layout_key_dict = {self.alice_pub["keyid"]: self.alice_pub}
        with self.assertRaises(RuleVerificationError):
            in_toto_verify(layout, layout_key_dict)

    def test_verify_failing_inspection_rules(self):
        """Test fail verification with failing inspection artifact rule."""
        layout = Metablock.load(self.layout_failing_inspection_rule_path)
        layout_key_dict = {self.alice_pub["keyid"]: self.alice_pub}
        with self.assertRaises(RuleVerificationError):
            in_toto_verify(layout, layout_key_dict)

    def test_verify_layout_signatures_fail_with_no_keys(self):
        """Layout signature verification fails when no keys are passed."""
        layout_metablock = Metablock(signed=Layout())
        with self.assertRaises(SignatureVerificationError):
            in_toto_verify(layout_metablock, {})

    def test_verify_layout_signatures_fail_with_malformed_signature(self):
        """Layout signature verification fails with malformed signatures."""
        layout_metablock = Metablock(signed=Layout())
        layout_metablock.create_signature(SignerStore.rsa)

        del layout_metablock.signatures[0]["sig"]
        layout_key_dict = {SignerStore.rsa_pub["keyid"]: SignerStore.rsa_pub}
        with self.assertRaises(SignatureVerificationError):
            in_toto_verify(layout_metablock, layout_key_dict)


class TestInTotoVerifyThresholds(unittest.TestCase):
    """Test verifylib functions related to signature thresholds.

    - verifylib.verify_link_signature_thresholds
    - verifylib.verify_threshold_constraints"""

    @classmethod
    def setUpClass(cls):
        """Load test keys from demo files."""

        cls.alice = SignerStore.rsa
        cls.alice_pubkey = SignerStore.rsa_pub
        cls.alice_keyid = cls.alice_pubkey["keyid"]

        cls.bob = SignerStore.ecdsa
        cls.bob_pubkey = SignerStore.ecdsa_pub
        cls.bob_keyid = cls.bob_pubkey["keyid"]

        cls.name = "test"
        cls.foo_hash = (
            "d65165279105ca6773180500688df4bdc69a2c7b771752f0a46ef120b7fd8ec3"
        )

    def test_thresholds_skip_unauthorized_links(self):
        """Ignore links with unauthorized signatures."""
        # Layout with one step, one authorized functionary and threshold 1
        layout = Layout(
            keys={self.bob_keyid: self.bob_pubkey},
            steps=[Step(name=self.name, pubkeys=[self.bob_keyid])],
        )

        # Signed links (one authorized the other one not)
        link_bob = Metablock(signed=Link(name=self.name))
        link_bob.create_signature(self.bob)
        link_alice = Metablock(signed=Link(name=self.name))
        link_alice.create_signature(self.alice)

        # The dictionary of links per step passed to the verify function
        chain_link_dict = {
            self.name: {self.bob_keyid: link_bob, self.alice_keyid: link_alice}
        }

        # The dictionary of links expected to be returned, not containing the
        # unauthorized link, but enough (threshold) authorized links
        expected_chain_link_dict = {self.name: {self.bob_keyid: link_bob}}
        # Verify signatures/thresholds
        returned_chain_link_dict = verify_link_signature_thresholds(
            layout, chain_link_dict
        )
        # Test that the returned dict is as expected
        self.assertDictEqual(returned_chain_link_dict, expected_chain_link_dict)

    def test_thresholds_skip_links_with_failing_signature(self):
        """Ignore links with failing signatures."""

        # Layout with one step, two authorized functionaries and threshold 1
        layout = Layout(
            keys={
                self.bob_keyid: self.bob_pubkey,
                self.alice_keyid: self.alice_pubkey,
            },
            steps=[
                Step(
                    name=self.name,
                    pubkeys=[self.bob_keyid, self.alice_keyid],
                    threshold=1,
                )
            ],
        )

        # Authorized links (one signed one not)
        link_bob = Metablock(signed=Link(name=self.name))
        link_bob.create_signature(self.bob)
        link_alice = Metablock(signed=Link(name=self.name))

        # The dictionary of links per step passed to the verify function
        chain_link_dict = {
            self.name: {self.bob_keyid: link_bob, self.alice_keyid: link_alice}
        }

        # The dictionary of links expected to be returned, not containing the
        # unauthorized link, but enough (threshold) authorized links
        expected_chain_link_dict = {self.name: {self.bob_keyid: link_bob}}

        # Verify signatures/thresholds
        returned_chain_link_dict = verify_link_signature_thresholds(
            layout, chain_link_dict
        )
        # Test that the returned dict is as expected
        self.assertDictEqual(returned_chain_link_dict, expected_chain_link_dict)

    def test_thresholds_fail_with_not_enough_valid_links(self):
        """Fail with not enough authorized links."""

        # Layout with one step, two authorized functionaries and threshold 2
        layout = Layout(
            keys={
                self.bob_keyid: self.bob_pubkey,
                self.alice_keyid: self.alice_pubkey,
            },
            steps=[
                Step(
                    name=self.name,
                    pubkeys=[self.bob_keyid, self.alice_keyid],
                    threshold=2,
                )
            ],
        )

        # Only one authorized and validly signed link
        link_bob = Metablock(signed=Link(name=self.name))
        link_bob.create_signature(self.bob)

        # The dictionary of links per step passed to the verify function
        chain_link_dict = {self.name: {self.bob_keyid: link_bob}}

        # Fail signature threshold verification with not enough links
        with self.assertRaises(ThresholdVerificationError):
            verify_link_signature_thresholds(layout, chain_link_dict)

    def test_threshold_constraints_fail_with_not_enough_links(self):
        """Fail with not enough links."""
        # Layout with one step and threshold 2
        layout = Layout(steps=[Step(name=self.name, threshold=2)])
        # Authorized (unsigned) link
        # This function does not care for signatures it just verifies if the
        # different links have recorded the same artifacts. Signature verification
        # happens earlier in the final product verification (see tests above)
        link_bob = Metablock(signed=Link(name=self.name))

        chain_link_dict = {
            self.name: {
                self.bob_keyid: link_bob,
            }
        }

        with self.assertRaises(ThresholdVerificationError):
            verify_threshold_constraints(layout, chain_link_dict)

    def test_threshold_constraints_fail_with_unequal_links(self):
        """Test that the links for a step recorded the same artifacts."""
        # Layout with one step and threshold 2
        layout = Layout(steps=[Step(name=self.name, threshold=2)])
        link_bob = Link(
            name=self.name, materials={"foo": {"sha256": self.foo_hash}}
        )
        # Cf. signing comment in test_thresholds_constraints_with_not_enough_links
        link_alice = Link(name=self.name)

        chain_link_dict = {
            self.name: {
                self.bob_keyid: link_bob,
                self.alice_keyid: link_alice,
            }
        }

        with self.assertRaises(ThresholdVerificationError):
            verify_threshold_constraints(layout, chain_link_dict)

    def test_threshold_constraints_pas_with_equal_links(self):
        """Pass threshold constraint verification with equal links."""
        # Layout with one step and threshold 2
        layout = Layout(steps=[Step(name=self.name, threshold=2)])
        # Two authorized links with equal artifact recordings (materials)
        # Cf. signing comment in test_thresholds_constraints_with_not_enough_links
        link_bob = Link(
            name=self.name, materials={"foo": {"sha256": self.foo_hash}}
        )
        link_alice = Link(
            name=self.name, materials={"foo": {"sha256": self.foo_hash}}
        )

        chain_link_dict = {
            self.name: {
                self.bob_keyid: link_bob,
                self.alice_keyid: link_alice,
            }
        }

        verify_threshold_constraints(layout, chain_link_dict)


@unittest.skipIf(not have_gpg(), "gpg not found")
class TestInTotoVerifyThresholdsGpgSubkeys(
    unittest.TestCase, TmpDirMixin, GPGKeysMixin
):
    """
    Test the following 8 scenarios for combinations of link authorization,
    where a link is either signed by a master or subkey (SIG), and the
    corresponding step authorizes either the master or subkey (AUTH), and the
    corresponding top level key in the layout key store is either a master key
    (bundle, i.e. with subkeys) or a subkey (KEY).

    M ... Masterkey
    S ... Subkey

    SIG AUTH KEY(bundle)| OK  | Comment
    ---------------------------------------------------------------
    M   M    M          | Yes | Normal scenario (*)
    M   M    S          | No  | Cannot find key in key store + cannot sign (*)
    M   S    M          | No  | Unallowed trust delegation + cannot sign (*)
    M   S    S          | No  | Unallowed trust delegation + cannot sign (*)
    S   M    M          | Yes | Allowed trust delegation
    S   M    S          | No  | Cannot associate keys
    S   S    M          | Yes | Can find key in key store
    S   S    S          | Yes | Generalizes to normal scenario

    (*) NOTE: Master keys with a subkey with signing capability always use that
    subkey, even if the master keyid is specified and has signing capability.


    Plus additional gpg subkey related threshold tests.

    """

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()
        cls.set_up_gpg_keys()

        master_key = securesystemslib._gpg.functions.export_pubkey(
            cls.gpg_key_0c8a17, cls.gnupg_home
        )
        sub_key = master_key["subkeys"][cls.gpg_key_d92439]

        # We need a gpg key without subkeys to test the normal scenario (M M M),
        # because keys with signing subkeys always use that subkey for signing.
        master_key2 = securesystemslib._gpg.functions.export_pubkey(
            cls.gpg_key_768c43, cls.gnupg_home
        )

        cls.pub_key_dict = {
            cls.gpg_key_0c8a17: master_key,
            cls.gpg_key_d92439: sub_key,
            cls.gpg_key_768c43: master_key2,
        }

        cls.step_name = "name"

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def _verify_link_signature_tresholds(self, sig_id, auth_id, key_id):
        """Helper to generate layout and signed links."""
        metablock = Metablock(signed=Link(name=self.step_name))
        metablock.sign_gpg(sig_id, self.gnupg_home)  # SIG

        chain_link_dict = {self.step_name: {sig_id: metablock}}  # SIG

        layout = Layout(
            steps=[Step(name=self.step_name, pubkeys=[auth_id])],  # AUTH
            keys={key_id: self.pub_key_dict[key_id]},  # KEY
        )
        return layout, chain_link_dict

    def test_verify_link_signature_thresholds__m_m_m(self):
        """Normal scenario."""
        layout, chain_link_dict = self._verify_link_signature_tresholds(
            self.gpg_key_768c43, self.gpg_key_768c43, self.gpg_key_768c43
        )

        # print("path: {}".format(os.environ['PATH']))
        verify_link_signature_thresholds(layout, chain_link_dict)

    def test_verify_link_signature_thresholds__m_m_s__m_s_m__m_s_s(self):
        """Cannot sign with master key if subkey is present."""
        # The scenarios MMS, MSM, MSS are impossible because we cannot sign
        # with a master key, if there is a subkey with signing capability
        # GPG will always use that subkey.
        # Even if gpg would use the masterkey, these scenarios are not allowed,
        # see table in docstring of testcase
        signature = securesystemslib._gpg.functions.create_signature(
            b"data", self.gpg_key_0c8a17, self.gnupg_home
        )

        self.assertTrue(signature["keyid"] == self.gpg_key_d92439)

    def test_verify_link_signature_thresholds__s_m_m(self):
        """Allowed trust delegation."""
        layout, chain_link_dict = self._verify_link_signature_tresholds(
            self.gpg_key_d92439, self.gpg_key_0c8a17, self.gpg_key_0c8a17
        )
        verify_link_signature_thresholds(layout, chain_link_dict)

    def test_verify_link_signature_thresholds__s_m_s(self):
        """Cannot associate keys."""
        layout, chain_link_dict = self._verify_link_signature_tresholds(
            self.gpg_key_d92439, self.gpg_key_0c8a17, self.gpg_key_d92439
        )
        with self.assertRaises(ThresholdVerificationError):
            verify_link_signature_thresholds(layout, chain_link_dict)

    def test_verify_link_signature_thresholds__s_s_m(self):
        """No trust delegation and can find key in key store."""
        layout, chain_link_dict = self._verify_link_signature_tresholds(
            self.gpg_key_d92439, self.gpg_key_d92439, self.gpg_key_0c8a17
        )
        verify_link_signature_thresholds(layout, chain_link_dict)

    def test_verify_link_signature_thresholds__s_s_s(self):
        """Generalizes to normal scenario."""
        layout, chain_link_dict = self._verify_link_signature_tresholds(
            self.gpg_key_d92439, self.gpg_key_d92439, self.gpg_key_d92439
        )
        verify_link_signature_thresholds(layout, chain_link_dict)

    def test_verify_subkey_thresholds(self):
        """Subkeys of same main key count only once towards threshold."""

        masterkey = "40e692c3ae03f6b88dff95d0d2c9fe930766998d"
        subkey1 = "35830aa342b9fea0178876b02b25647ff0ef59fe"
        subkey2 = "732d722578f71a9ec967a64bfead922c91eb7351"

        link1 = Metablock(signed=Link(name=self.step_name))
        link1.sign_gpg(subkey1, self.gnupg_home)
        link2 = Metablock(signed=Link(name=self.step_name))
        link2.sign_gpg(subkey2, self.gnupg_home)

        chain_link_dict = {self.step_name: {subkey1: link1, subkey2: link2}}

        layout = Layout(
            steps=[Step(name=self.step_name, pubkeys=[masterkey], threshold=2)],
            keys={
                masterkey: securesystemslib._gpg.functions.export_pubkey(
                    masterkey, self.gnupg_home
                )
            },
        )
        with self.assertRaises(ThresholdVerificationError):
            verify_link_signature_thresholds(layout, chain_link_dict)

    def test_verify_thresholds_skip_expired_key(self):
        """Verify that a link signed with an expired key is skipped.

        NOTE: This test would be a better fit for `TestInTotoVerifyThresholds`,
        but we make use of `TestInTotoVerifyThresholdsGpgSubkeys`'s gpg setup here.

        """
        expired_key_id = "e8ac80c924116dabb51d4b987cb07d6d2c199c7c"
        expired_key = securesystemslib._gpg.functions.export_pubkey(
            expired_key_id, self.gnupg_home
        )

        # Chain link dict containing a single link for a single step
        # The link's signature is (supposedly) signed by an expired key and
        # hence does not count towards the link threshold as defined in the layout.
        chain_link_dict = {
            self.step_name: {
                expired_key_id: Metablock(
                    signed=Link(name=self.step_name),
                    signatures=[
                        {
                            "keyid": expired_key_id,
                            "other_headers": "deadbeef",
                            "signature": "deadbeef",
                        }
                    ],
                )
            }
        }
        layout = Layout(
            steps=[
                Step(name=self.step_name, pubkeys=[expired_key_id], threshold=1)
            ],
            keys={expired_key_id: expired_key},
        )

        with (
            self.assertRaises(ThresholdVerificationError),
            patch("in_toto.verifylib.LOG") as mock_log,
        ):
            verify_link_signature_thresholds(layout, chain_link_dict)

        self.assertEqual(mock_log.info.call_args[0][0], "Skipping link. %s")
        self.assertIsInstance(mock_log.info.call_args[0][1], KeyExpirationError)


class TestVerifySublayouts(unittest.TestCase, TmpDirMixin):
    """Tests verifylib.verify_sublayouts(layout, reduced_chain_link_dict).
    Call with one-step super layout that has a sublayout (demo layout)."""

    @classmethod
    def setUpClass(cls):
        """Creates and changes into temporary directory and prepares two layouts.
        The superlayout, which has one step and its sublayout, which is the usual
        demo layout (write code, package, inspect tar)."""
        # Find demo files
        demo_files = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "demo_files"
        )

        # find where the scripts directory is located.
        scripts_directory = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "scripts"
        )

        # Create and change into temporary directory
        cls.set_up_test_dir()

        # Copy demo files to temp dir
        for fn in os.listdir(demo_files):
            shutil.copy(os.path.join(demo_files, fn), cls.test_dir)

        # copy portable scripts over
        shutil.copytree(scripts_directory, "scripts")

        # Import sub layout signing (private) and verifying (public) keys
        alice = SignerStore.rsa
        alice_pub = SignerStore.rsa_pub

        # From the perspective of the superlayout, the sublayout is treated as
        # a link corresponding to a step, hence needs a name.
        sub_layout_name = "sub_layout"

        # Sublayout links are expected in a directory relative to the superlayout's
        # link directory
        sub_layout_link_dir = SUBLAYOUT_LINK_DIR_FORMAT.format(
            name=sub_layout_name, keyid=alice_pub["keyid"]
        )

        for sublayout_link_name in glob.glob("*.link"):
            dest_path = os.path.join(sub_layout_link_dir, sublayout_link_name)
            os.renames(sublayout_link_name, dest_path)

        # Copy, sign and dump sub layout as link from template
        layout_template = Metablock.load("demo.layout.template")
        sub_layout = copy.deepcopy(layout_template)
        sub_layout_path = FILENAME_FORMAT.format(
            step_name=sub_layout_name, keyid=alice_pub["keyid"]
        )
        sub_layout.create_signature(alice)
        sub_layout.dump(sub_layout_path)

        # Create super layout that has only one step, the sublayout
        cls.super_layout = Layout()
        cls.super_layout.keys[alice_pub["keyid"]] = alice_pub
        sub_layout_step = Step(
            name=sub_layout_name, pubkeys=[alice_pub["keyid"]]
        )
        cls.super_layout.steps.append(sub_layout_step)

        # Load the super layout links (i.e. the sublayout)
        cls.super_layout_links = load_links_for_layout(cls.super_layout, ".")

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def test_verify_demo_as_sublayout(self):
        """Test super layout's passing sublayout verification."""
        verify_sublayouts(self.super_layout, self.super_layout_links, ".", 10)


class TestInTotoVerifyMultiLevelSublayouts(unittest.TestCase, TmpDirMixin):
    """Test verifylib.in_toto_verify with multiple levels of sublayouts."""

    def test_verify_multi_level_sublayout(self):
        # Create and change into temporary directory
        self.set_up_test_dir()

        keys = {
            "alice_priv": SignerStore.rsa,
            "alice_pub": SignerStore.rsa_pub,
            "bob_priv": SignerStore.ecdsa,
            "bob_pub": SignerStore.ecdsa_pub,
            "carl_priv": SignerStore.ed25519,
            "carl_pub": SignerStore.ed25519_pub,
        }

        # Create layout hierarchy

        # Root layout
        # The root layout is the layout that will be passed to `in_toto_verify`
        # It only has one step which is a sublayout, into which verification
        # recurses. Only the root layout and root layout verification key will be
        # passed to verification.
        root_layout_pub_key_dict = {
            keys["alice_pub"]["keyid"]: keys["alice_pub"]
        }

        root_layout_step_name = "delegated-to-bob"

        root_layout = Metablock(
            signed=Layout(
                keys={keys["bob_pub"]["keyid"]: keys["bob_pub"]},
                steps=[
                    Step(
                        name=root_layout_step_name,
                        pubkeys=[keys["bob_pub"]["keyid"]],
                    )
                ],
            )
        )
        root_layout.create_signature(keys["alice_priv"])

        # Sublayout (first level)
        # The first level sublayout wil be treated as a link from the
        # superlayout's perspective and loaded from the current working directory.
        # The link for the only step of this sublayout will be placed in a
        # namespaced subdir, that link itself is a sublayout (subsublayout).
        bobs_layout_name = FILENAME_FORMAT.format(
            step_name=root_layout_step_name, keyid=keys["bob_pub"]["keyid"]
        )

        bobs_layout_link_dir = SUBLAYOUT_LINK_DIR_FORMAT.format(
            name=root_layout_step_name, keyid=keys["bob_pub"]["keyid"]
        )
        os.mkdir(bobs_layout_link_dir)

        bobs_layout_step_name = "delegated-to-carl"

        bobs_layout = Metablock(
            signed=Layout(
                keys={keys["carl_pub"]["keyid"]: keys["carl_pub"]},
                steps=[
                    Step(
                        name=bobs_layout_step_name,
                        pubkeys=[keys["carl_pub"]["keyid"]],
                    )
                ],
            )
        )
        bobs_layout.create_signature(keys["bob_priv"])
        bobs_layout.dump(bobs_layout_name)

        # Subsublayout (second level)
        # The subsublayout will be placed in the namespaced link dir
        # of its superlayout (sublayout from the root layout's perspective), for
        # for which it serves as link.
        carls_layout_name = FILENAME_FORMAT.format(
            step_name=bobs_layout_step_name, keyid=keys["carl_pub"]["keyid"]
        )

        carls_layout_path = os.path.join(
            bobs_layout_link_dir, carls_layout_name
        )
        carls_layout = Metablock(signed=Layout())
        carls_layout.create_signature(keys["carl_priv"])
        carls_layout.dump(carls_layout_path)

        in_toto_verify(root_layout, root_layout_pub_key_dict)

        self.tear_down_test_dir()


class TestSublayoutVerificationMatchRule(unittest.TestCase, TmpDirMixin):
    """Tests a sublayout and checks if a MATCH rule is successful after sublayout
    is resolved into a summary link."""

    def test_verify_sublayout_match_rule(self):
        # Find demo files
        demo_files = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "demo_files"
        )

        script_files = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "scripts"
        )

        # Create and change into temporary directory
        self.set_up_test_dir()

        keys = {
            "alice_priv": SignerStore.rsa,
            "alice_pub": SignerStore.rsa_pub,
            "bob_priv": SignerStore.ecdsa,
            "bob_pub": SignerStore.ecdsa_pub,
            "carl_priv": SignerStore.ed25519,
            "carl_pub": SignerStore.ed25519_pub,
        }

        # Create layout hierarchy

        # Root layout
        # The root layout is the layout that will be passed to `in_toto_verify`
        # It only has one step which is a sublayout, into which verification
        # recurses. Only the root layout and root layout verification key will be
        # passed to verification.
        root_layout_pub_key_dict = {
            keys["alice_pub"]["keyid"]: keys["alice_pub"]
        }

        root_layout_step_name = "delegated-to-bob"

        root_layout = Metablock(
            signed=Layout(
                keys={keys["bob_pub"]["keyid"]: keys["bob_pub"]},
                steps=[
                    Step(
                        name=root_layout_step_name,
                        pubkeys=[keys["bob_pub"]["keyid"]],
                        expected_products=[
                            [
                                "MATCH",
                                "foo.tar.gz",
                                "WITH",
                                "PRODUCTS",
                                "FROM",
                                root_layout_step_name,
                            ],
                            ["DISALLOW", "*"],
                        ],
                    )
                ],
            )
        )
        root_layout.create_signature(keys["alice_priv"])

        # Sublayout (first level)
        # The sublayout will be treated as a link from the superlayout's
        # perspective and loaded from the current working directory. The links for
        # the steps of this sublayout will be placed in a namespaced subdir.
        bobs_layout_name = FILENAME_FORMAT.format(
            step_name=root_layout_step_name, keyid=keys["bob_pub"]["keyid"]
        )

        bobs_layout_link_dir = SUBLAYOUT_LINK_DIR_FORMAT.format(
            name=root_layout_step_name, keyid=keys["bob_pub"]["keyid"]
        )
        os.mkdir(bobs_layout_link_dir)

        bobs_layout = Metablock.load(
            os.path.join(demo_files, "demo.layout.template")
        )
        bobs_layout.create_signature(keys["bob_priv"])
        bobs_layout.dump(bobs_layout_name)
        shutil.copy2(
            os.path.join(demo_files, "write-code.776a00e2.link"),
            bobs_layout_link_dir,
        )
        shutil.copy2(
            os.path.join(demo_files, "package.2f89b927.link"),
            bobs_layout_link_dir,
        )
        shutil.copy2(os.path.join(demo_files, "foo.tar.gz"), ".")
        shutil.copytree(script_files, os.path.join(".", "scripts"))

        in_toto_verify(root_layout, root_layout_pub_key_dict)

        self.tear_down_test_dir()


class TestGetSummaryLink(unittest.TestCase, TmpDirMixin):
    """Tests verifylib.get_summary_link(layout, reduced_chain_link_dict).
    Pass two step demo layout and according link files and verify the
    returned summary link.
    """

    @classmethod
    def setUpClass(cls):
        """Creates and changes into temporary directory and prepares two layouts.
        The superlayout, which has one step and its sublayout, which is the usual
        demo layout (write code, package, inspect tar)."""

        # Find demo files
        demo_files = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "demo_files"
        )

        # Create and change into temporary directory
        cls.set_up_test_dir()

        # Copy demo files to temp dir
        for fn in os.listdir(demo_files):
            shutil.copy(os.path.join(demo_files, fn), cls.test_dir)

        cls.demo_layout = Metablock.load("demo.layout.template")
        cls.code_link = Metablock.load("package.2f89b927.link")
        cls.package_link = Metablock.load("write-code.776a00e2.link")
        cls.demo_links = {
            "write-code": cls.code_link.signed,
            "package": cls.package_link.signed,
        }

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def test_get_summary_link_from_demo_layout(self):
        """Create summary link from demo link files and compare properties."""
        sum_link = get_summary_link(
            self.demo_layout.signed, self.demo_links, ""
        )

        self.assertEqual(sum_link._type, self.code_link.signed._type)
        self.assertEqual(sum_link.name, "")
        self.assertEqual(sum_link.materials, self.code_link.signed.materials)

        self.assertEqual(sum_link.products, self.package_link.signed.products)
        self.assertEqual(sum_link.command, self.package_link.signed.command)
        self.assertEqual(
            sum_link.byproducts, self.package_link.signed.byproducts
        )
        self.assertEqual(
            sum_link.byproducts.get("return-value"),
            self.package_link.signed.byproducts.get("return-value"),
        )


if __name__ == "__main__":
    unittest.main()
