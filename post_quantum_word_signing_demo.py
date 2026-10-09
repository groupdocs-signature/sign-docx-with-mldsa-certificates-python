# Topic: Sign Word documents with post-quantum ML-DSA certificates and verify them.
# Uses GroupDocs.Signature for Python via .NET 26.9+: DigitalSignOptions with an ML-DSA
# PFX file, DigitalVerifyOptions with the public certificate, and search for digital
# signatures.

import os
import sys

import groupdocs.signature as signature
from groupdocs.signature.domain import SignatureType
from groupdocs.signature.options import DigitalSignOptions, DigitalVerifyOptions

DOCS = "documents"
RESULT = "Result"

SOURCE_DOCX = os.path.join(DOCS, "contract.docx")

# Self-signed ML-DSA test certificates, valid from 2026 to 2056.
# Use certificates from your own CA in production.
MLDSA44_PFX = os.path.join(DOCS, "mldsa44.pfx")
MLDSA65_PFX = os.path.join(DOCS, "mldsa65.pfx")
MLDSA87_PFX = os.path.join(DOCS, "mldsa87.pfx")
MLDSA65_CER = os.path.join(DOCS, "mldsa65.cer")
CERTIFICATE_PASSWORD = "1234567890"


def apply_license() -> None:
    # Point this at your .lic file to remove evaluation limits.
    # Get a free temporary licence: https://purchase.groupdocs.com/temporary-license
    license_path = "REPLACE_WITH_YOUR_LICENSE_PATH"
    if os.path.exists(license_path):
        signature.License().set_license(license_path)
        print("[license] applied")
    else:
        print("[license] no licence set - running in evaluation mode")


def sign_with_mldsa_certificate(source_path: str, pfx_path: str,
                                output_path: str) -> str:
    """
    Signs a Word document with a post-quantum ML-DSA certificate.

    Remarks:
        Builds a DigitalSignOptions from the path of a PFX file that holds an ML-DSA key,
        sets its password, and calls sign - exactly as for an RSA certificate. ML-DSA
        (FIPS 204) is the NIST post-quantum signature algorithm, meant to stay secure
        when quantum computers can break RSA and ECDSA. Since GroupDocs.Signature 26.9
        this works for Word documents (DOCX, DOC, ODT and the other Word formats) on
        every supported platform: where the underlying runtime cannot read ML-DSA keys,
        the certificate read by the Word engine is used instead. PDF, spreadsheets and
        presentations cannot be signed with ML-DSA yet, and there is no standard XML-DSig
        identifier for ML-DSA, so Microsoft Word may not validate such a signature. The
        signed DigitalSignature comes back in result.succeeded, and its certificate
        resolves attributes dynamically through the .NET bridge - certificate.subject
        works even though dir() on it lists nothing. Returns the subject of the signing
        certificate.
    """
    with signature.Signature(source_path) as sign:
        options = DigitalSignOptions(pfx_path)
        options.password = CERTIFICATE_PASSWORD

        result = sign.sign(output_path, options)
        for created in result.succeeded:
            certificate = getattr(created, "certificate", None)
            subject = getattr(certificate, "subject", None)
            if subject:
                return str(subject)
        return "(no certificate returned)"


def sign_with_each_security_level(source_path: str) -> dict:
    """
    Signs the same Word document with ML-DSA-44, ML-DSA-65 and ML-DSA-87 certificates.

    Remarks:
        Calls sign with a DigitalSignOptions for each of the three ML-DSA parameter sets.
        They trade size for strength: ML-DSA-44 targets NIST security category 2,
        ML-DSA-65 category 3 and ML-DSA-87 category 5, and both the key and the signature
        grow with the level, which the output file sizes show directly. ML-DSA-65 is a
        balanced choice when no policy prescribes a level; some government profiles, such
        as CNSA 2.0, require ML-DSA-87. Writes one signed file per level into the result
        folder and returns a dict mapping each level and file name to its size in bytes.
    """
    levels = (
        ("ML-DSA-44", MLDSA44_PFX),
        ("ML-DSA-65", MLDSA65_PFX),
        ("ML-DSA-87", MLDSA87_PFX),
    )

    sizes = {}
    for level, pfx_path in levels:
        suffix = level.replace("-", "").lower()
        file_name = f"contract-{suffix}.docx"
        output_path = os.path.join(RESULT, file_name)

        with signature.Signature(source_path) as sign:
            options = DigitalSignOptions(pfx_path)
            options.password = CERTIFICATE_PASSWORD
            sign.sign(output_path, options)

        sizes[f"{level} -> {file_name}"] = os.path.getsize(output_path)

    return sizes


def verify_signer(signed_path: str, certificate_path: str,
                  password: str = None) -> bool:
    """
    Checks that a signed Word document was signed by the owner of a given certificate.

    Remarks:
        Builds a DigitalVerifyOptions from a certificate file and calls verify.
        Recipients only need the signer's public certificate, a .cer file with no
        password; a PFX with its password works too, which is why the password argument
        is optional here. The result is valid only when the signature matches the
        document content and its certificate has the same serial number and thumbprint as
        the one supplied, so a document signed by somebody else, or changed after
        signing, comes back as not valid rather than raising. Returns True when the
        verification succeeds.
    """
    with signature.Signature(signed_path) as sign:
        options = DigitalVerifyOptions(certificate_path)
        if password is not None:
            options.password = password

        return sign.verify(options).is_valid


def list_digital_signatures(signed_path: str) -> int:
    """
    Lists the digital signatures of a document with their certificates and validity.

    Remarks:
        Calls search with SignatureType.DIGITAL, which returns DigitalSignature objects
        rather than a raw list of certificates. Each one carries the signing certificate,
        the signing time in sign_time and an is_valid flag saying whether the signature
        still matches the document. Use it to show who signed an incoming document before
        processing it, and note that for an ML-DSA signature the certificate returned is
        the public certificate. Prints one line per signature and returns the number
        found.
    """
    with signature.Signature(signed_path) as sign:
        found = sign.search(SignatureType.DIGITAL)
        for item in found:
            certificate = getattr(item, "certificate", None)
            subject = getattr(certificate, "subject", None)
            print(f"Digital signature: {subject}, "
                  f"signed {item.sign_time:%Y-%m-%d %H:%M:%SZ}, valid: {item.is_valid}")

        return len(found)


def main() -> int:
    os.makedirs(DOCS, exist_ok=True)
    os.makedirs(RESULT, exist_ok=True)
    apply_license()

    if not os.path.exists(SOURCE_DOCX):
        print(f"Missing source document: {os.path.abspath(SOURCE_DOCX)}", file=sys.stderr)
        return 1

    signed_docx = os.path.join(RESULT, "contract-signed.docx")
    signer = sign_with_mldsa_certificate(SOURCE_DOCX, MLDSA65_PFX, signed_docx)
    print(f"Signed with ML-DSA-65 by: {signer}")

    print("Signed files for each ML-DSA security level:")
    for name, size in sign_with_each_security_level(SOURCE_DOCX).items():
        print(f"  {name}: {size} bytes")

    by_signer = verify_signer(signed_docx, MLDSA65_CER)
    by_other = verify_signer(signed_docx, MLDSA44_PFX, CERTIFICATE_PASSWORD)
    print(f"Valid for the signer's public certificate : {by_signer}")
    print(f"Valid for another signer's certificate    : {by_other}")

    found = list_digital_signatures(signed_docx)
    print(f"Results: {os.path.abspath(RESULT)}")

    return 0 if (by_signer and not by_other and found == 1) else 2


if __name__ == "__main__":
    sys.exit(main())
