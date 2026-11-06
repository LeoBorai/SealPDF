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

/* Like sealpdf_sign, with a visible signature: a box on page `page` (1-based) that shows who
 * signed and when. The rectangle is in the page's default user space, in points with the origin
 * at the bottom-left, the space a PDF's /Rect uses; /Rotate is not applied to it. It must have an
 * area and overlap the page's visible area (its crop box), or the call fails and writes nothing.
 * The time in the text is shown in the system's time zone. Same threading rules as
 * sealpdf_sign. */
int sealpdf_sign_visible(const SealpdfCerts *certs, const char *input, const char *output,
                         const char *alias, unsigned int page,
                         double llx, double lly, double urx, double ury, char **error);

/* Where a visible signature goes when nothing else is asked, the same place `sealpdf sign
 * --visible` uses: the page number (1-based) and rectangle, in the same space as above. Any of
 * the five out-pointers may be NULL. Returns 0 on success; otherwise a non-zero code and, when
 * `error` is not NULL, a message if the file cannot be read or is not a PDF. Reads the file, so
 * call it off the main thread for a large PDF. */
int sealpdf_default_signature_box(const char *path, unsigned int *page,
                                  double *llx, double *lly, double *urx, double *ury,
                                  char **error);

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
