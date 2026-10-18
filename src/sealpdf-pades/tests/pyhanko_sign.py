"""Signs a PDF with pyHanko, as a third party: pyhanko_sign.py IN P12 PASSWORD OUT FIELD."""
import sys

from pyhanko.sign import fields, signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

pdf_in, p12, password, pdf_out, field = sys.argv[1:6]
signer = signers.SimpleSigner.load_pkcs12(p12, passphrase=password.encode())
with open(pdf_in, "rb") as f:
    writer = IncrementalPdfFileWriter(f)
    fields.append_signature_field(writer, fields.SigFieldSpec(sig_field_name=field))
    with open(pdf_out, "wb") as out:
        signers.sign_pdf(writer, signers.PdfSignatureMetadata(field_name=field), signer=signer, output=out)
