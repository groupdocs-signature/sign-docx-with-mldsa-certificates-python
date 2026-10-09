# Post-Quantum ML-DSA Signing for Word Documents in Python

[![Product Page](https://img.shields.io/badge/Product%20Page-2865E0?style=for-the-badge&logo=appveyor&logoColor=white)](https://github.com/groupdocs-signature/GroupDocs.Signature-Docs)
[![Docs](https://img.shields.io/badge/Docs-2865E0?style=for-the-badge&logo=Hugo&logoColor=white)](https://docs.groupdocs.com/signature/python-net/)
[![Blog](https://img.shields.io/badge/Blog-2865E0?style=for-the-badge&logo=WordPress&logoColor=white)](https://blog.groupdocs.com/categories/groupdocs.signature-product-family/)
[![Free Support](https://img.shields.io/badge/Free%20Support-2865E0?style=for-the-badge&logo=Discourse&logoColor=white)](https://forum.groupdocs.com/c/signature/13)
[![Temporary License](https://img.shields.io/badge/Temporary%20License-2865E0?style=for-the-badge&logo=rocket&logoColor=white)](https://purchase.groupdocs.com/temp-license/100124)

## 📖 About This Repository

ML-DSA signing is a GroupDocs.Signature capability for Python that signs Word documents with a post-quantum certificate instead of an RSA or ECDSA one. ML-DSA is the signature algorithm NIST standardised as FIPS 204 in 2024, and support for it in Word formats arrived in GroupDocs.Signature 26.9.

This repository signs the same contract four times - once with ML-DSA-65, then once at each of the three NIST security levels - verifies the result against the signer's public certificate and against someone else's, and reads the signature back out of the file. `python post_quantum_word_signing_demo.py` runs all of it and prints the sizes, which is where the interesting part shows up.

## The Challenge

A signature is a promise that lasts as long as the document does. That is the awkward part of post-quantum migration: a contract signed today with RSA-2048 may still need to be defensible in 2045, and the attack does not have to arrive before then - it only has to arrive before the document stops mattering. An adversary who stores signed documents now can forge new ones later, once a quantum computer can recover the private key from the public one.

For encryption this is discussed as harvest-now-decrypt-later. For signatures the exposure is narrower but longer-lived: nothing you signed stays verifiable as *yours* once the key can be derived. Documents with retention measured in decades - contracts, deeds, medical consent, engineering sign-off - are the ones where the clock already matters, and some government profiles have set dates. CNSA 2.0 requires ML-DSA-87 for national-security systems.

GroupDocs.Signature for Python via .NET signs Word documents with ML-DSA certificates through the same `DigitalSignOptions` used for RSA. Key points:

- **One API for both** - a PFX holding an ML-DSA key is passed exactly like an RSA one, so adopting it is a certificate change rather than a code change
- **Three parameter sets** - ML-DSA-44, ML-DSA-65 and ML-DSA-87 map to NIST security categories 2, 3 and 5
- **Verification by public certificate** - recipients need only a `.cer` file, no password and no private key
- **Signature discovery** - `search` returns each signature with its certificate, signing time and validity flag

Word formats only, for now. PDF, spreadsheets and presentations cannot be signed with ML-DSA yet, and because no standard XML-DSig identifier for ML-DSA exists, Microsoft Word itself may not validate the signature even though GroupDocs.Signature does.

## Prerequisites

Python 3.9 or later on a 64-bit interpreter, and `groupdocs-signature-net` 26.10.0 - installed with `pip install -r requirements.txt`. The package carries its own .NET runtime, so nothing else needs installing.

The three ML-DSA test certificates and the source contract ship in `documents/`, so the sample runs with no setup. They are self-signed, valid from 2026 to 2056, and exist only to make the demo runnable - replace them with certificates from your own CA before signing anything real.

## Repository Structure

```
sign-docx-with-mldsa-certificates-python/
│
├── post_quantum_word_signing_demo.py
├── requirements.txt
├── documents/
│   ├── contract.docx
│   ├── mldsa44.pfx
│   ├── mldsa65.pfx
│   ├── mldsa87.pfx
│   └── mldsa65.cer
└── Result/
    ├── contract-signed.docx
    ├── contract-mldsa44.docx
    ├── contract-mldsa65.docx
    └── contract-mldsa87.docx
```

The `.pfx` files hold a private key and its certificate; `mldsa65.cer` is the matching public certificate, included to show that verification needs nothing secret. `Result/` holds the output of a real run, so the sizes quoted below can be checked against the files rather than taken on trust.

## Code Examples

### Signing a Word document with an ML-DSA certificate

The ML-DSA key is in a PFX, and it is passed exactly as an RSA one would be.

```python
with signature.Signature(source_path) as sign:
    options = DigitalSignOptions(pfx_path)
    options.password = CERTIFICATE_PASSWORD

    result = sign.sign(output_path, options)
    for created in result.succeeded:
        certificate = getattr(created, "certificate", None)
        subject = getattr(certificate, "subject", None)
        if subject:
            return str(subject)
```

There is one Python-specific trap in those last lines. The certificate on a `DigitalSignature` is a bridge object that resolves attributes dynamically, so `certificate.subject` returns `CN=GroupDocs.Signature MLDSA65 test` while `dir()` on the same object lists nothing at all. I inspected it with `dir()` first and concluded the subject was not exposed, which was wrong - reading it directly works. Code that tests for the attribute before reading it will skip a subject that is there.

### Comparing the three security levels

```python
levels = (
    ("ML-DSA-44", MLDSA44_PFX),
    ("ML-DSA-65", MLDSA65_PFX),
    ("ML-DSA-87", MLDSA87_PFX),
)

for level, pfx_path in levels:
    with signature.Signature(source_path) as sign:
        options = DigitalSignOptions(pfx_path)
        options.password = CERTIFICATE_PASSWORD
        sign.sign(output_path, options)

    sizes[f"{level} -> {file_name}"] = os.path.getsize(output_path)
```

This is the part worth running. The three levels differ in strength and in size, and the output makes the trade concrete - from a 132 KB source contract:

| Level | NIST category | Signed file |
|---|---|---|
| ML-DSA-44 | 2 | 138,202 bytes |
| ML-DSA-65 | 3 | 140,650 bytes |
| ML-DSA-87 | 5 | 143,971 bytes |

About 6 KB separates the weakest from the strongest, on one signature. That is negligible for a contract and worth counting if you are signing a million small files, which is the only real argument for not simply choosing ML-DSA-87. ML-DSA-65 is a sensible default when no policy names a level.

### Verifying against a certificate

```python
with signature.Signature(signed_path) as sign:
    options = DigitalVerifyOptions(certificate_path)
    if password is not None:
        options.password = password

    return sign.verify(options).is_valid
```

The sample calls this twice: once with `mldsa65.cer`, the public certificate of the key that signed, and once with `mldsa44.pfx`, a different signer's certificate. The first returns `True`, the second `False`. A mismatch is a `False`, not an exception, because "signed by someone else" is an answer rather than an error - the check covers both the document content and the certificate's serial number and thumbprint.

### Reading signatures out of a document

```python
with signature.Signature(signed_path) as sign:
    found = sign.search(SignatureType.DIGITAL)
    for item in found:
        certificate = getattr(item, "certificate", None)
        subject = getattr(certificate, "subject", None)
        print(f"Digital signature: {subject}, "
              f"signed {item.sign_time:%Y-%m-%d %H:%M:%SZ}, valid: {item.is_valid}")
```

`search` with `SignatureType.DIGITAL` gives back `DigitalSignature` objects carrying the certificate, `sign_time` and `is_valid`. This is what to call on an incoming document before processing it - it answers who signed and whether the signature still matches, without needing to know in advance which certificate to expect.

### Should I migrate to ML-DSA now?

Not wholesale, and not for everything. The useful question is retention: if a document must stay verifiable for longer than RSA-2048 is expected to hold, signing it post-quantum now avoids re-signing later with a key nobody trusts. Start with long-lived Word documents, keep RSA where recipients validate in Word itself, and treat the certificate as the thing you migrate rather than the code.

## Related Topics to Explore

* **Sign a Document with a Digital Certificate in Python** - the full `DigitalSignOptions` reference, including appearance, reason and time stamps: [Read the article →](https://docs.groupdocs.com/signature/python-net/sign-document-with-digital-signature/)

* **Verify Digital Signatures in Word and PDF Documents** - verification criteria beyond a certificate file, such as subject and issuer matching: [Read the article →](https://docs.groupdocs.com/signature/python-net/verify-digital-signatures-in-the-document/)

* **Search for Digital e-Signatures in a Document** - the search API used in the last example, with its options: [Read the article →](https://docs.groupdocs.com/signature/python-net/search-for-digital-e-signatures/)

* **Post-Quantum ML-DSA Signing in .NET** - the same four operations from the C# side, if your stack spans both: [Read the article →](https://blog.groupdocs.com/signature/sign-word-with-post-quantum-certificates-net/)

## Keywords

`post-quantum`, `ml-dsa`, `fips 204`, `word signing`, `docx signature`, `digital signature`, `groupdocs signature`, `python signing`, `quantum-safe`, `cnsa 2.0`, `mldsa44`, `mldsa65`, `mldsa87`, `nist security category`, `pfx`, `public certificate`, `digitalsignoptions`, `digitalverifyoptions`, `signature search`, `python via .net`, `26.9`, `dilithium`

## Support

For technical support, visit:
- [Free Support Forum](https://forum.groupdocs.com/c/signature/13)
- [Product Documentation](https://docs.groupdocs.com/signature/python-net/)
- [Get Temporary License](https://purchase.groupdocs.com/temp-license/100124)
