# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from pytss_toolslike import toolslike_encdec
from tpm2_pytss.constants import TPM2_ALG, TPMA_OBJECT, TPM2_RH
from tpm2_pytss.types import TPM2B_DIGEST


class ToolsLikeTest(unittest.TestCase):
    def test_toolslike_enc_friendly_int(self):
        enc = toolslike_encdec()
        ev = enc.encode(TPM2_RH.OWNER)
        self.assertEqual(ev, "owner")

        ev = enc.encode(TPM2_ALG.LAST + 1)
        self.assertEqual(ev, int(TPM2_ALG.LAST + 1))

    def test_toolslike_enc_friendly_intlist(self):
        enc = toolslike_encdec()
        ev = enc.encode(TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.SIGN_ENCRYPT)
        self.assertEqual(ev, "userwithauth|sign")

    def test_toolslike_enc_simple_tpm2b(self):
        enc = toolslike_encdec()
        d = TPM2B_DIGEST(b"\x01\x02\x03\x04")
        ev = enc.encode(d)
        self.assertEqual(ev, "0x01020304")

        ev = enc.encode(TPM2B_DIGEST())
        self.assertEqual(ev, None)

    def test_toolslike_dec_friendly_int(self):
        dec = toolslike_encdec()
        dv = dec.decode(TPM2_ALG(), "sha256")
        self.assertEqual(dv, TPM2_ALG.SHA256)

        dv = dec.decode(TPM2_ALG(), int(TPM2_ALG.SHA256))
        self.assertEqual(dv, TPM2_ALG.SHA256)

    def test_toolslike_dec_friendly_intlist(self):
        dec = toolslike_encdec()
        dv = dec.decode(TPMA_OBJECT(), "userwithauth|sign")
        self.assertEqual(dv, TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.SIGN_ENCRYPT)

        dv = dec.decode(
            TPMA_OBJECT(), int(TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.SIGN_ENCRYPT)
        )
        self.assertEqual(dv, TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.SIGN_ENCRYPT)

    def test_toolslike_dec_simple_tpm2b(self):
        dec = toolslike_encdec()
        dv = dec.decode(TPM2B_DIGEST(), "ffff")
        self.assertEqual(dv, TPM2B_DIGEST(b"\xff\xff"))

        dv = dec.decode(TPM2B_DIGEST(), "0xAAAA")
        self.assertEqual(dv, TPM2B_DIGEST(b"\xaa\xaa"))
