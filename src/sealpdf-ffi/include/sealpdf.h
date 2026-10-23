#ifndef SEALPDF_H
#define SEALPDF_H

#ifdef __cplusplus
extern "C" {
#endif

/* The signing certificates of a key store, listed once and kept. */
typedef struct SealpdfCerts SealpdfCerts;

/* Every `char *` returned or written through `error` belongs to the caller and is released
 * with sealpdf_string_free. Strings passed in are UTF-8 and null-terminated. */

/* Lists the Keychain's signing certificates. On failure returns NULL and, when `error` is not
 * NULL, stores a message in it. */
SealpdfCerts *sealpdf_certs_open(char **error);

/* Lists the certificates in the PKCS#12 file (.p12 or .pfx) at `path`, unlocked with
 * `password`. A wrong password fails with a message and NULL. */
SealpdfCerts *sealpdf_certs_open_pkcs12(const char *path, const char *password, char **error);

/* How many certificates are offered. 0 for NULL. */
unsigned long sealpdf_certs_count(const SealpdfCerts *certs);

/* The alias of certificate `index`, or NULL when out of range. */
char *sealpdf_certs_alias(const SealpdfCerts *certs, unsigned long index);

/* Signs the PDF at `input` with the certificate `alias` and writes the result to `output`. The
 * input is never changed. Returns 0 on success; otherwise a non-zero code and, when `error` is
 * not NULL, a message. Blocks until done, and while macOS asks for permission to use the key,
 * so call it off the main thread. One call at a time per handle. */
int sealpdf_sign(const SealpdfCerts *certs, const char *input, const char *output,
                 const char *alias, char **error);

/* How many signatures the PDF at `path` carries, document timestamps not counted. Decodes no
 * signature, so it is cheap. Returns -1 and, when `error` is not NULL, a message if the file
 * cannot be read as a PDF. */
long sealpdf_signature_count(const char *path, char **error);

/* Lists and checks the signatures of the PDF at `path`. Returns the report as UTF-8 JSON, the
 * same text `sealpdf verify --json` prints, or NULL and, when `error` is not NULL, a message if
 * the file cannot be read, is not a PDF, or is encrypted. Call it off the main thread. */
char *sealpdf_inspect(const char *path, char **error);

void sealpdf_certs_free(SealpdfCerts *certs);
void sealpdf_string_free(char *string);

#ifdef __cplusplus
}
#endif

#endif
