"""Prints one tab-separated line per signature of a PDF: SIG, field, intact, valid, entire_file.

Trust is not checked (the test certificates are self-made): only that the signature is intact,
that its cryptography verifies, and that it covers the whole file.
"""
import sys

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.status import SignatureCoverageLevel

with open(sys.argv[1], "rb") as f:
    reader = PdfFileReader(f)
    for sig in reader.embedded_signatures:
        try:
            status = validate_pdf_signature(sig)
            intact, valid = status.intact, status.valid
            entire = status.coverage == SignatureCoverageLevel.ENTIRE_FILE
        except Exception as e:  # trust path errors for self-made certificates are not failures here
            intact = valid = entire = False
            print(f"# {type(e).__name__}: {e}", file=sys.stderr)
        print("SIG", sig.field_name, intact, valid, entire, sep="\t")
