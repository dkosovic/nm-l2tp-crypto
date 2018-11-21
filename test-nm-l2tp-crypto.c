#include "nm-default.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <nm-utils.h>
#include <nm-errors.h>
#include "nm-l2tp-crypto-openssl.h"
#include "nm-l2tp-crypto-nss.h"

#define TEST_CERT_DIR "./certs/"
#define TEST_NSS_DIR "./nss-db/"
#define TEST_PEM_DIR "./pem-output/"

char *test_files[] = {
	"ca-no-ending-newline.pem",
	"pkcs8-decrypted.der",
	"pkcs8-enc-key.pem",
	"pkcs8-noenc-key.pem",
	"strongswan_ecCert.pem",
	"strongswan_ecKey.pem",
	"test2_ca_cert.pem",
	"test2-cert.p12",
	"test2_key_and_cert.pem",
	"test-aes-key.pem",
	"test_ca_cert.der",
	"test_ca_cert.pem",
	"test-ca-cert.pem",
	"test-cert.p12",
	"test_key_and_cert.pem",
	"test-key-and-cert.pem",
	"test-key-only-decrypted.der",
	"test-key-only-decrypted.pem",
	"test-key-only.pem",
	"test-key-only-traditional.der",
	NULL
};

char *pkey_password[][2] = {
	{"test_key_and_cert.pem", "test"},
	{"test-key-only.pem", "test"},
	{"test2_key_and_cert.pem", "12345testing"},
	{"test-aes-128-key.pem", "test-aes-password"},
	{"test-aes-256-key.pem", "test-aes-password"},
	{NULL, NULL}
};

char *pkcs12_password[][2] = {
	{"test-cert.p12", "test"},
	{"test2-cert.p12", "12345testing"},
	{NULL, NULL}
};

char *pkey_cert_ca_password[][4] = {
	{"sunKey.pem", "sunCert.pem", "strongswanCert.pem", NULL},
	{NULL, NULL, NULL, NULL}
};


char *cryptoFileFormatToString(NML2tpCryptoFileFormat format) {
	switch (format) {
		case NM_L2TP_CRYPTO_FILE_FORMAT_UNKNOWN:
			return "NM_L2TP_CRYPTO_FILE_FORMAT_UNKNOWN";
			break;
		case NM_L2TP_CRYPTO_FILE_FORMAT_X509_DER:
			return "NM_L2TP_CRYPTO_FILE_FORMAT_X509_DER";
			break;
		case NM_L2TP_CRYPTO_FILE_FORMAT_X509_PEM:
			return "NM_L2TP_CRYPTO_FILE_FORMAT_X509_PEM";
			break;
		case NM_L2TP_CRYPTO_FILE_FORMAT_PKCS8_DER:
			return "NM_L2TP_CRYPTO_FILE_FORMAT_PKCS8_DER";
			break;
		case NM_L2TP_CRYPTO_FILE_FORMAT_PKCS8_PEM:
			return "NM_L2TP_CRYPTO_FILE_FORMAT_PKCS8_PEM";
			break;
		case NM_L2TP_CRYPTO_FILE_FORMAT_PKCS12:
			return "NM_L2TP_CRYPTO_FILE_FORMAT_PKCS12";
			break;
		case NM_L2TP_CRYPTO_FILE_FORMAT_RSA_PKEY_DER:
			return "NM_L2TP_CRYPTO_FILE_FORMAT_RSA_PKEY_DER";
			break;
		case NM_L2TP_CRYPTO_FILE_FORMAT_RSA_PKEY_PEM:
			return "NM_L2TP_CRYPTO_FILE_FORMAT_RSA_PKEY_PEM";
			break;
		case NM_L2TP_CRYPTO_FILE_FORMAT_DSA_PKEY_DER:
			return "NM_L2TP_CRYPTO_FILE_FORMAT_DSA_PKEY_DER";
			break;
		case NM_L2TP_CRYPTO_FILE_FORMAT_DSA_PKEY_PEM:
			return "NM_L2TP_CRYPTO_FILE_FORMAT_DSA_PKEY_PEM";
			break;
		case NM_L2TP_CRYPTO_FILE_FORMAT_ECDSA_PKEY_DER:
			return "NM_L2TP_CRYPTO_FILE_FORMAT_ECDSA_PKEY_DER";
			break;
		case NM_L2TP_CRYPTO_FILE_FORMAT_ECDSA_PKEY_PEM:
			return "NM_L2TP_CRYPTO_FILE_FORMAT_ECDSA_PKEY_PEM";
			break;
	}

	return "NM_L2TP_CRYPTO_FILE_FORMAT_UNKNOWN";
}

void test_crypto_file_format (char *filename)
{
	GError *err = NULL;
	NML2tpCryptoFileFormat format = NM_L2TP_CRYPTO_FILE_FORMAT_UNKNOWN;
	gboolean need_password;
	gs_free char *filepath = NULL;

	filepath = g_build_filename (TEST_CERT_DIR, (const char *) filename, NULL);
	printf("testing crypto_file_format %s :\n", filename);
	format = crypto_file_format (filepath, &need_password, &err);
	if ( err != NULL ) {
		fprintf(stderr, "\terr = %s\n", err->message);
		g_error_free(err);
		err = NULL;
	}
	printf("\tformat = %s , need password = %d\n", cryptoFileFormatToString(format), need_password);
}

void test_crypto_pkcs12_get_subject_name (const char *filename, const char *password)
{
	GError *err = NULL;
	GString *subject_name_str = NULL;
	GByteArray *subject_name_asn1 = NULL;
	gs_free char *filepath = NULL;

	filepath = g_build_filename (TEST_CERT_DIR, (const char *) filename, NULL);
	printf("testing crypto_pkcs12_get_subject_name %s :\n", filename);
	crypto_pkcs12_get_subject_name (filepath, password, &subject_name_str, &subject_name_asn1, &err);
	if ( err != NULL ) {
		fprintf(stderr, "\terr = %s\n", err->message);
		g_error_free(err);
		err = NULL;
	}

	printf("\tsubject_name=%s\n", subject_name_str->str);

	printf("\tasn1dn:#");
	for (size_t i = 0; i < subject_name_asn1->len; i++)
		printf("%02x", subject_name_asn1->data[i]);
	printf("\n");

	g_string_free (subject_name_str, TRUE);
	g_byte_array_free (subject_name_asn1, TRUE);
}

void test_crypto_create_pkcs12_data (const char *pkey_filename,
                                            const char *cert_filename,
                                            const char *ca_filename,
                                            const char *password)
{
	GError *err = NULL;
	gs_free char *pkey_filepath = NULL;
	gs_free char *cert_filepath = NULL;
	gs_free char *ca_filepath = NULL;
	GByteArray *p12_array;

	pkey_filepath = g_build_filename (TEST_CERT_DIR, (const char *) pkey_filename, NULL);
	cert_filepath = g_build_filename (TEST_CERT_DIR, (const char *) cert_filename, NULL);
	if (ca_filename)
		ca_filepath = g_build_filename (TEST_CERT_DIR, (const char *) ca_filename, NULL);

	printf("testing crypto_create_pkcs12_data,\n  pkey='%s',\n  cert='%s',\n  CA='%s':\n", pkey_filepath, cert_filepath, (ca_filepath?ca_filepath:""));
	p12_array = crypto_create_pkcs12_data (pkey_filepath, cert_filepath, ca_filepath, password, NULL, &err);
	if (err != NULL ) {
		fprintf(stderr, "\terr = %s\n", err->message);
		g_error_free(err);
		return;
	}

	printf("testing crypto_import_nss_pkcs12\n");
	crypto_import_nss_pkcs12 (p12_array, password, &err);
	if (err != NULL ) {
		fprintf(stderr, "\terr = %s\n", err->message);
		g_error_free(err);
	}
	g_byte_array_free (p12_array, TRUE);
}

void test_crypto_decrypt_pkcs12_data (const char *filename, const char *password)
{
	GError *err = NULL;
	gs_free char *filepath = NULL;
	GByteArray *p12_array;

	filepath = g_build_filename (TEST_CERT_DIR, (const char *) filename, NULL);

	printf("testing crypto_decrypt_pkcs12_data '%s'\n", filepath);
	p12_array = crypto_decrypt_pkcs12_data (filepath, password, NULL, &err);
	if (err != NULL ) {
		fprintf(stderr, "\terr = %s\n", err->message);
		g_error_free(err);
		return;
	}

	printf("testing crypto_import_nss_pkcs12\n");
	crypto_import_nss_pkcs12 (p12_array, password, &err);
	if (err != NULL ) {
		fprintf(stderr, "\terr = %s\n", err->message);
		g_error_free(err);
	}
	g_byte_array_free (p12_array, TRUE);
}

void test_crypto_pkcs12_to_pem_files (const char *p12_filename, const char *password)
{
	GError *err = NULL;
	gs_free char *p12_filepath = NULL;
	gs_free char *pkey_filepath;
	gs_free char *cert_filepath;
	gs_free char *ca_filepath;

	p12_filepath = g_build_filename (TEST_CERT_DIR, (const char *) p12_filename, NULL);
	pkey_filepath = g_build_filename (TEST_PEM_DIR, (const char *) "pkey.pem", NULL);
	cert_filepath = g_build_filename (TEST_PEM_DIR, (const char *) "cert.pem", NULL);
	ca_filepath = g_build_filename (TEST_PEM_DIR, (const char *) "ca.pem", NULL);

	printf("testing crypto_pkcs12_to_pem_files '%s'\n", p12_filepath);
	printf("  pkey='%s',\n  cert='%s',\n  CA='%s':\n", pkey_filepath, cert_filepath, ca_filepath);
	crypto_pkcs12_to_pem_files (p12_filepath, password, pkey_filepath, cert_filepath, ca_filepath, &err);
	if (err != NULL ) {
		fprintf(stderr, "\terr = %s\n", err->message);
		g_error_free(err);
		return;
	}
}

void test_crypto_to_pem_file ()
{
	GError *err = NULL;
	gs_free char *ca_in_filepath = NULL;
	gs_free char *pkey_in_filepath = NULL;
	gs_free char *ca_filepath;
	gs_free char *pkey_decrypted_filepath;
	gs_free char *pkey_encrypted_filepath;

	ca_in_filepath = g_build_filename (TEST_CERT_DIR, (const char *) "test_ca_cert.der", NULL);
	pkey_in_filepath = g_build_filename (TEST_CERT_DIR, (const char *) "pkcs8-decrypted.der", NULL);
	ca_filepath = g_build_filename (TEST_PEM_DIR, (const char *) "der2pem-ca.pem", NULL);
	pkey_decrypted_filepath = g_build_filename (TEST_PEM_DIR, (const char *) "der2pem-pkey-decrypted.pem", NULL);
	pkey_encrypted_filepath = g_build_filename (TEST_PEM_DIR, (const char *) "der2pem-pkey-encrypted.pem", NULL);

	printf("testing crypto_x509_der_to_pem_file '%s'\n", ca_in_filepath);
	printf("  CA='%s'\n", ca_filepath);
	crypto_x509_der_to_pem_file (ca_in_filepath, ca_filepath, &err);
	if (err != NULL ) {
		fprintf(stderr, "\terr = %s\n", err->message);
		g_error_free(err);
		return;
	}

	printf("testing crypto_pkey_der_to_pem_file '%s'\n", pkey_in_filepath);
	printf("  pkey='%s'\n", pkey_decrypted_filepath);
	crypto_pkey_der_to_pem_file (pkey_in_filepath, NULL, pkey_decrypted_filepath, &err);
	if (err != NULL ) {
		fprintf(stderr, "\terr = %s\n", err->message);
		g_error_free(err);
		return;
	}

	printf("testing crypto_pkey_der_to_pem_file '%s'\n", pkey_in_filepath);
	printf("  pkey='%s'\n", pkey_encrypted_filepath);
	crypto_pkey_der_to_pem_file (pkey_in_filepath, "password", pkey_encrypted_filepath, &err);
	if (err != NULL ) {
		fprintf(stderr, "\terr = %s\n", err->message);
		g_error_free(err);
		return;
	}
}

int main (int argc, char **argv) {
	GError *err = NULL;
	int i;

	crypto_init_openssl ();

	printf("### Testing File Format ####\n");
	i = 0;
	while (test_files[i] != NULL) {
		test_crypto_file_format(test_files[i]);
		i++;
	}

	printf("\n### Testing PKCS#12 Subject Name ####\n");
	i = 0;
	while (pkcs12_password[i][0] != NULL) {
		test_crypto_pkcs12_get_subject_name (pkcs12_password[i][0], pkcs12_password[i][1]);
		i++;
	}


	printf("\n### Testing NSS database import ####\n");

	/* Setup NSS database directory */
	if (g_mkdir_with_parents (TEST_NSS_DIR, 0755) != 0) {
		fprintf(stderr, "failed to create NSS dir '%s' : %s\n", TEST_NSS_DIR, g_strerror (errno));
		crypto_deinit_openssl();
		exit(1);
	}

	crypto_init_nss (TEST_NSS_DIR, &err);
	if ( err != NULL ) {
		fprintf(stderr, "\terr = %s\n", err->message);
		g_error_free(err);
		err = NULL;
	}

	i = 0;
	while (pkey_cert_ca_password[i][0] != NULL) {
		test_crypto_create_pkcs12_data (pkey_cert_ca_password[i][0],
		                                       pkey_cert_ca_password[i][1],
		                                       pkey_cert_ca_password[i][2],
		                                       pkey_cert_ca_password[i][3]);
		i++;
	}

	i = 0;
	while (pkcs12_password[i][0] != NULL) {
		test_crypto_decrypt_pkcs12_data (pkcs12_password[i][0],
		                                 pkcs12_password[i][1]);
		i++;
	}

	printf("\n### Testing PEM output functions ####\n");

	/* Setup output pem directory */
	if (g_mkdir_with_parents (TEST_PEM_DIR, 0755) != 0) {
		fprintf(stderr, "failed to create PEM output dir '%s' : %s\n", TEST_PEM_DIR, g_strerror (errno));
		crypto_deinit_openssl();
		exit(1);
	}

	i = 0;
	while (pkcs12_password[i][0] != NULL) {
		test_crypto_pkcs12_to_pem_files (pkcs12_password[i][0],
		                                 pkcs12_password[i][1]);
		i++;
	}

	test_crypto_to_pem_file();

	crypto_deinit_openssl();
	crypto_deinit_nss (&err);
	if ( err != NULL ) {
		fprintf(stderr, "\terr = %s\n", err->message);
		g_error_free(err);
		err = NULL;
	}
}

