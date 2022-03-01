# pytss_toolslike

Encode and decode TPM 2.0 types and constants in a tools like manner.

# Example

```python
>>> from tpm2_pytss.constants import TPMA_OBJECT
>>> from pytss_toolslike import toolslike_encdec
>>> ed = toolslike_encdec()
>>> ed.encode(TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.USERWITHAUTH)
'userwithauth|sign'
>>> 
```
