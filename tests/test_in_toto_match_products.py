"""Test in_toto_match_products.py."""

import unittest
from pathlib import Path
from unittest.mock import patch

import in_toto.in_toto_match_products as cli
from in_toto.models.metadata import Metadata


class TestInTotoMatchProducts(unittest.TestCase):
    """Basic tests for in_toto_match_products cli.

    Only tests cli <-> api interaction, api itself is tested in runlib.
    """

    link = str(
        Path(__file__).parent / "demo_files" / "write-code.776a00e2.link"
    )

    def test_check_args(self):
        """Assert api args for cli args."""

        args = [
            "--link",
            self.link,
            "--paths",
            "foo",
            "bar",
            "--exclude",
            "f*",
            "b*",
            "--lstrip-paths",
            "f",
            "b",
        ]
        expected_arg = Metadata.load(self.link).signed
        expected_kwargs = {
            "paths": ["foo", "bar"],
            "exclude_patterns": ["f*", "b*"],
            "lstrip_paths": ["f", "b"],
        }

        # Mock sys.argv in cli tool to mock cli invocation, and mock api
        # function to only check how it is called, w/o executing.
        with (
            patch.object(cli.sys, "argv", ["<cmd>"] + args),
            patch.object(
                cli, "match_products", return_value=(set(),) * 3
            ) as api,
            self.assertRaises(SystemExit),
        ):
            cli.main()

        api.assert_called_with(expected_arg, **expected_kwargs)

    def test_check_exit(self):
        """Assert cli exit codes for api return values."""
        test_data = [
            ((set(), set(), set()), 0),
            (({"foo"}, set(), set()), 1),
            ((set(), {"foo"}, set()), 1),
            ((set(), set(), {"foo"}), 1),
        ]

        # Mock sys.argv in cli tool to mock cli invocation, and mock api
        # function to control return values, w/o executing.
        for api_return_value, cli_return_code in test_data:
            with (
                patch.object(cli.sys, "argv", ["<cmd>", "-l", self.link]),
                patch.object(
                    cli, "match_products", return_value=api_return_value
                ),
                self.assertRaises(SystemExit) as error_ctx,
            ):
                cli.main()

            self.assertEqual(
                error_ctx.exception.code,
                cli_return_code,
                f"api returned: {api_return_value}",
            )


if __name__ == "__main__":
    unittest.main()
