# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  _signer.py

<Author>
  Pradyumna Krishna <git@onpy.in>

<Started>
  Jan 26, 2023

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides in-toto flavored Signer implementations

"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import securesystemslib.gpg.exceptions as gpg_exceptions
import securesystemslib.gpg.functions as gpg
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from securesystemslib import exceptions
from securesystemslib.signer import (
    CryptoSigner,
    Key,
    SecretsHandler,
    Signature,
    Signer,
    SSlibKey,
)


def load_crypto_signer_from_pkcs8_file(
    path: str, password: Optional[bytes] = None
) -> CryptoSigner:
    """Internal helper to load CryptoSigner from PKCS8/PEM file."""
    with open(path, "rb") as f:
        data = f.read()

    private_key = load_pem_private_key(data, password)
    signer = CryptoSigner(private_key)

    return signer


def load_public_key_from_file(path: str) -> Dict[str, Any]:
    """Internal helper to load key from SubjectPublicKeyInfo/PEM file."""
    with open(path, "rb") as f:
        data = f.read()

    crypto_public_key = load_pem_public_key(data)
    key = SSlibKey.from_crypto(crypto_public_key)

    # NOTE: Would be nice to support `Key` instances natively in in-toto.
    # Until then we keep using the in-toto -tailored dict representation of
    # `Key`, which is expected in metadata model and verifylib API.
    key_dict = key.to_dict()
    key_dict["keyid"] = key.keyid

    return key_dict


class GPGSignature(Signature):
    """A container class containing information about a gpg signature.
    Besides the signature, it also contains other meta information
    needed to uniquely identify the key used to generate the signature.

    Attributes:
      keyid: HEX string used as a unique identifier of the key.
      signature: HEX string representing the signature.
      other_headers: HEX representation of additional GPG headers.
    """

    def __init__(
        self,
        keyid: str,
        signature: str,
        other_headers: str,
    ):
        super().__init__(keyid, signature)
        self.other_headers = other_headers

    @classmethod
    def from_dict(cls, signature_dict: Dict) -> "GPGSignature":
        """Creates a ``GPGSignature`` object from its JSON/dict
        representation.

        Arguments:
          signature_dict: Dict containing valid "keyid", "signature" and
            "other_fields" fields.
        Raises:
          KeyError: If any of the "keyid", "sig" or "other_headers" fields
            are missing from the signature_dict.
        Returns:
          ``GPGSignature`` instance.
        """

        return cls(
            signature_dict["keyid"],
            signature_dict["signature"],
            signature_dict["other_headers"],
        )

    def to_dict(self) -> Dict:
        """Returns the JSON-serializable dictionary representation of self."""
        return {
            "keyid": self.keyid,
            "signature": self.signature,
            "other_headers": self.other_headers,
        }


class GPGSigner(Signer):
    """A in-toto gpg implementation of the ``Signer`` interface.
    Provides a sign method to generate a cryptographic signature with gpg, using
    an RSA, DSA or EdDSA private key identified by the keyid on the instance.

    Arguments:
      keyid: The keyid of the gpg signing keyid. If not passed the default
        key in the keyring is used.
      homedir: Path to the gpg keyring. If not passed the default keyring
        is used.
    """

    def __init__(
        self, keyid: Optional[str] = None, homedir: Optional[str] = None
    ):
        self.keyid = keyid
        self.homedir = homedir

    @property
    def public_key(self) -> Key:
        raise NotImplementedError  # pragma: no cover

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "GPGSigner":
        raise NotImplementedError(
            "Incompatible with private key URIs"
        )  # pragma: no cover

    def sign(self, payload: bytes) -> GPGSignature:
        """Signs a given payload by the key assigned to the ``GPGSigner``
        instance. Calls the gpg command line utility to sign the passed content
        with the key identified by the passed keyid from the gpg keyring at the
        passed homedir.

        Arguments:
          payload: The bytes to be signed.
        Raises:
          securesystemslib.exceptions.FormatError:
            If the keyid is invalid.
          ValueError: the gpg command failed to create a valid signature.
          OSError: the gpg command is not present or non-executable.
          securesystemslib.exceptions.UnsupportedLibraryError: the gpg command is
            not available, or the cryptography library is not installed.
          securesystemslib.gpg.exceptions.CommandError: the gpg command returned a
            non-zero exit code.
          securesystemslib.gpg.exceptions.KeyNotFoundError: the used gpg version is
            not fully supported and no public key can be found for short keyid.
          Returns:
            Returns a ``GPGSignature`` class instance.
        """

        sig_dict = gpg.create_signature(payload, self.keyid, self.homedir)
        return GPGSignature(**sig_dict)


@dataclass
class GPGKey(Key):
    """A container class representing public key portion of a GPG key.
    Provides a verify method to verify a cryptographic signature with a
    gpg-style rsa, dsa or ecdsa public key on the instance.

    Attributes:
      type: Key type, e.g. "rsa", "dsa" or "ecdsa".
      method: GPG Key Scheme, For example:
        "pgp+rsa-pkcsv1.5", "pgp+dsa-fips-180-2", and "pgp+eddsa-ed25519".
      hashes: list of GPG Hash Algorithms, e.g. "pgp+SHA2".
      keyval: Opaque key content.
      keyid: Key identifier that is unique within the metadata it is used in.
        Keyid is not verified to be the hash of a specific representation
        of the key.
      creation_time: Unix timestamp when GPG key was created.
      validity_period: Validity of the GPG Keys in days.
      subkeys: A dictionary containing keyid and GPG subkey.
    """

    # pylint: disable=too-many-instance-attributes

    type: str
    method: str
    hashes: List[str]
    keyval: Dict[str, str]
    keyid: str
    creation_time: Optional[int] = None
    validity_period: Optional[int] = None
    subkeys: Optional[Dict[str, "GPGKey"]] = None

    @classmethod
    def from_dict(cls, keyid: str, key_dict: Dict[str, Any]):
        """Creates ``GPGKey`` object from its json/dict representation.
        Raises:
          KeyError, TypeError: Invalid arguments.
        """
        subkeys_dict = key_dict.get("subkeys")

        gpg_subkeys = None
        if subkeys_dict:
            gpg_subkeys = {
                keyid_: GPGKey.from_dict(keyid_, subkey_dict)
                for (keyid_, subkey_dict) in subkeys_dict.items()
            }

        return cls(
            key_dict["type"],
            key_dict["method"],
            key_dict["hashes"],
            key_dict["keyval"],
            keyid,
            key_dict.get("creation_time"),
            key_dict.get("validity_period"),
            gpg_subkeys,
        )

    @classmethod
    def from_legacy_dict(cls, key_dict: Dict[str, Any]):
        """Create GPGKey from legacy dictionary representation."""

        keyid = key_dict["keyid"]
        return cls.from_dict(keyid, key_dict)

    def to_dict(self):
        """Returns the dictionary representation of self."""

        key_dict = {
            "method": self.method,
            "type": self.type,
            "hashes": self.hashes,
            "keyid": self.keyid,
            "keyval": self.keyval,
        }

        if self.creation_time:
            key_dict["creation_time"] = self.creation_time
        if self.validity_period:
            key_dict["validity_period"] = self.validity_period
        if self.subkeys:
            subkeys_dict = {
                keyid: subkey.to_dict()
                for (keyid, subkey) in self.subkeys.items()
            }
            key_dict["subkeys"] = subkeys_dict

        return key_dict

    @classmethod
    def from_keyring(cls, keyid, homedir=None):
        """Creates ``GPGKey`` object from GnuPG Keyring."""

        pubkey_dict = gpg.export_pubkey(keyid, homedir)
        return cls.from_dict(keyid, pubkey_dict)

    def verify_signature(self, signature: GPGSignature, data: bytes) -> None:
        """Verifies a given payload by the key assigned to the GPGKey
        instance.

        Arguments:
          signature: A ``GPGSignature`` class instance.
          data: The bytes to be verified.
        """

        try:
            if not gpg.verify_signature(
                signature.to_dict(), self.to_dict(), data
            ):
                raise exceptions.UnverifiedSignatureError(
                    f"Failed to verify signature by {self.keyid}"
                )
        except (
            exceptions.FormatError,
            exceptions.UnsupportedLibraryError,
            gpg_exceptions.KeyExpirationError,
        ) as e:
            raise exceptions.VerificationError(
                f"Unknown failure to verify signature by {self.keyid}"
            ) from e
