# SPDX-License-Identifier: GPL-3.0-or-later

from tpm2_pytss.encoding import base_encdec
from tpm2_pytss.constants import TPM_FRIENDLY_INT, TPMA_FRIENDLY_INTLIST
from tpm2_pytss.types import TPM2B_SIMPLE_OBJECT
from typing import Union, List
from binascii import unhexlify


class toolslike_encdec(base_encdec):
    """Encode TPM types in a tpm2-tools like manner

    Args:
        use_lists (bool): if TPM attributes (such as TPMA_OBJECT) should be encoded as lists instead a string, defaults to False
        strict (bool): If a exception should be raised for unknown fields during decoding, defaults to False.
        case_insensitive (bool): If field names should be case insensitive during decoding, defaults to False.
    """

    def __init__(
        self,
        use_lists: bool = False,
        strict: bool = False,
        case_insensitive: bool = True,
    ):
        self._use_lists = use_lists
        super().__init__(strict=strict, case_insensitive=case_insensitive)

    def encode_friendly_int(self, val: TPM_FRIENDLY_INT) -> Union[str, int]:
        """Encode a TPM_FRIENDLY_INT value

        Args:
            val (TPM_FRIENDLY_INT): The value to encode

        Returns:
            A string if value matches as constant, an int otherwise
        """
        t = type(val)
        if t.contains(val):
            return str(val)
        return int(val)

    def encode_friendly_intlist(
        self, val: TPMA_FRIENDLY_INTLIST
    ) -> Union[str, List[str]]:
        """Encode a TPMA_FRIENDLY_INTLIST value

        Args:
            val (TPMA_FRIENDLY_INTLIST): The value to encode

        Returns:
            A string of the set attributes, or a list of strings if use_lists is True
        """
        if self._use_lists:
            al = list()
            at = type(val)
            for a in at.iterator():
                if a & val:
                    al.append(str(a))
            return al
        return str(val)

    def encode_simple_tpm2b(self, val: TPM2B_SIMPLE_OBJECT) -> Union[str, None]:
        """Encode a TPM2B_SIMPLE_OBJECT

        Args:
            val (TPM2B_SIMPLE_OBJECT): The value to encode

        Returns:
            A hex encoded string prefixed with 0x, or None if the value is empty
        """
        if len(val) == 0:
            return None
        return "0x" + str(val)

    def decode_friendly_int(
        self, dst: TPM_FRIENDLY_INT, src: Union[str, int]
    ) -> TPM_FRIENDLY_INT:
        """Decode a TPM_FRIENDLY_INT value

        Args:
            dst (TPM_FRIENDLY_INT): A TPM_FRIENDLY_INT instance to use as a type
            src (Union[str, int]): The value to decode

        Returns:
            An instance of the dst type with the decoded value
        """
        if isinstance(src, str):
            return type(dst).parse(src)
        return type(dst)(src)

    def decode_friendly_intlist(
        self, dst: TPMA_FRIENDLY_INTLIST, src: Union[str, int, List[str]]
    ) -> TPMA_FRIENDLY_INTLIST:
        """Decode a TPMA_FRIENDLY_INTLIST value

        Args:
            dst (TPMA_FRIENDLY_INTLIST): A TPMA_FRIENDLY_INTLIST instance to use as a type
            src (Union[str, int, List[str]]): The value to decode

        Returns:
            An instance of the dst type with the decoded value
        """
        if isinstance(src, list):
            attr = type(dst)
            for e in src:
                attr = attr & attr.parse(e)
            return attr
        elif isinstance(src, str):
            return type(dst).parse(src)
        return type(dst)(src)

    def decode_simple_tpm2b(
        self, dst: TPM2B_SIMPLE_OBJECT, src: str
    ) -> TPM2B_SIMPLE_OBJECT:
        """Decode a TPM2B_SIMPLE_OBJECT value

        Args:
            dst (TPM2B_SIMPLE_OBJECT): The TPM2B_SIMPLE_OBJECT instance to store the decoded value in
            src (str): A hex encoded string, with an optional "0x" prefix

        Returns:
            dst with the decoded value
        """
        if src[0:2].lower() == "0x":
            src = src[2:]
        dst.buffer = unhexlify(src)
        return dst
