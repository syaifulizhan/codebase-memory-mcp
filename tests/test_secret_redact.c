/* Secret-content redaction (fork hardening). Fixture secrets are assembled from
 * split literals so this file never carries a scannable credential itself. */
#include "test_framework.h"

#include "foundation/compat.h"
#include "foundation/secret_redact.h"

#include <stdlib.h>
#include <string.h>

static int count_char(const char *s, char c) {
    int n = 0;
    for (; *s; s++) {
        n += *s == c;
    }
    return n;
}

/* Redacts `input`, asserts the marker appears and `secret` is gone. */
static int expect_redacted(const char *input, const char *secret, const char *marker) {
    bool changed = false;
    char *out = cbm_redact_secrets(input, &changed);
    int ok = out && changed && strstr(out, marker) && (!secret || !strstr(out, secret)) &&
             count_char(out, '\n') == count_char(input, '\n');
    free(out);
    return ok;
}

static int expect_unchanged(const char *input) {
    bool changed = true;
    char *out = cbm_redact_secrets(input, &changed);
    int ok = out && !changed && strcmp(out, input) == 0;
    free(out);
    return ok;
}

TEST(redact_aws_access_key) {
    ASSERT_TRUE(expect_redacted("id = \"AK"
                                "IAIOSFODNN7EXAMPLE\"\n",
                                "IOSFODNN7EXAMPLE", "[REDACTED:aws-access-key-id]"));
    ASSERT_TRUE(expect_redacted("AS"
                                "IAIOSFODNN7EXAMPLE",
                                "IOSFODNN7EXAMPLE", "[REDACTED:aws-access-key-id]"));
    PASS();
}

TEST(redact_github_tokens) {
    ASSERT_TRUE(expect_redacted("t=gh"
                                "p_abcdefghijklmnopqrstuvwxyz0123456789",
                                "abcdefghijkl", "[REDACTED:github-token]"));
    ASSERT_TRUE(expect_redacted("t=gh"
                                "s_abcdefghijklmnopqrstuvwxyz0123456789",
                                "abcdefghijkl", "[REDACTED:github-token]"));
    ASSERT_TRUE(expect_redacted("t=github"
                                "_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz",
                                "ABCDEFG0", "[REDACTED:github-token]"));
    PASS();
}

TEST(redact_openai_and_anthropic_keys) {
    ASSERT_TRUE(expect_redacted("k = 's"
                                "k-proj-AbCdEf0123456789GhIjKlMn'",
                                "AbCdEf0123456789", "[REDACTED:openai-key]"));
    ASSERT_TRUE(expect_redacted("k = 's"
                                "k-ant-api03-AbCdEf0123456789GhIjKlMn-xyz'",
                                "AbCdEf0123456789", "[REDACTED:anthropic-key]"));
    PASS();
}

TEST(redact_slack_google_stripe_jwt) {
    ASSERT_TRUE(expect_redacted("x=xo"
                                "xb-1234567890-abcdefghijkl",
                                "1234567890-abcdefghijkl", "[REDACTED:slack-token]"));
    ASSERT_TRUE(expect_redacted("key: AI"
                                "zaSyA1234567890abcdefghijklmnopqrstuv",
                                "A1234567890abc", "[REDACTED:google-api-key]"));
    ASSERT_TRUE(expect_redacted("pay = 's"
                                "k_live_51Habcdef0123456789xyz'",
                                "51Habcdef0123456789", "[REDACTED:stripe-key]"));
    ASSERT_TRUE(expect_redacted("pay = 'r"
                                "k_live_51Habcdef0123456789xyz'",
                                "51Habcdef0123456789", "[REDACTED:stripe-key]"));
    ASSERT_TRUE(expect_redacted("a=ey"
                                "JhbGciOiJIUzI1NiJ9.ey"
                                "JzdWIiOiIxMjM0NTY3ODkwIn0.abc_DEF-123",
                                "JzdWIiOiIx", "[REDACTED:jwt]"));
    PASS();
}

TEST(redact_pem_block_keeps_line_count) {
    const char *pem =
        "a\n-----BEGIN RSA "
        "PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
        "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n-----END RSA "
        "PRIVATE KEY-----\nb\n";
    bool changed = false;
    char *out = cbm_redact_secrets(pem, &changed);
    ASSERT_NOT_NULL(out);
    ASSERT_TRUE(changed);
    ASSERT_NOT_NULL(strstr(out, "[REDACTED:pem-private-key]"));
    ASSERT_NULL(strstr(out, "MIIBOgIBAAJB"));
    ASSERT_NULL(strstr(out, "KUpRKfFL"));
    ASSERT_EQ(count_char(out, '\n'), count_char(pem, '\n'));
    ASSERT_TRUE(strncmp(out, "a\n", 2) == 0);
    ASSERT_TRUE(strlen(out) >= 2 && strcmp(out + strlen(out) - 2, "b\n") == 0);
    free(out);
    PASS();
}

TEST(redact_pem_without_end_and_windowed_body) {
    /* BEGIN with no END (window cut the block): redact to the end. */
    ASSERT_TRUE(expect_redacted("-----BEGIN OPENSSH "
                                "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n",
                                "b3BlbnNzaC1rZXk", "[REDACTED:pem-private-key]"));
    /* Window that starts mid-block: bare base64 body line. */
    ASSERT_TRUE(
        expect_redacted("MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n",
                        "MIIBOgIBAAJB", "[REDACTED:pem-body]"));
    PASS();
}

TEST(redact_secret_assignments_value_only) {
    bool changed = false;
    char *out = cbm_redact_secrets("const db_password = \"hunter2hunter2xyz\";\n", &changed);
    ASSERT_NOT_NULL(out);
    ASSERT_TRUE(changed);
    ASSERT_STR_EQ(out, "const db_password = \"[REDACTED:secret-assignment]\";\n");
    free(out);
    ASSERT_TRUE(expect_redacted("{\"api_key\": \"abcdef0123456789zz\"}", "abcdef0123456789",
                                "\"api_key\": \"[REDACTED:secret-assignment]\""));
    ASSERT_TRUE(expect_redacted("clientSecret: 'zzzzzzzzzzzzzzzz1'", "zzzzzzzzzzzzzzzz1",
                                "[REDACTED:secret-assignment]"));
    ASSERT_TRUE(expect_redacted("token := \"abcdefghij0123456789\"", "abcdefghij",
                                "[REDACTED:secret-assignment]"));
    PASS();
}

TEST(redact_has_no_false_positives_on_normal_code) {
    ASSERT_TRUE(expect_unchanged("const tokenizer = \"whitespace-and-more-text\";\n"));
    ASSERT_TRUE(expect_unchanged("int skip_tokens = count_tokens(input);\n"));
    ASSERT_TRUE(expect_unchanged("password = \"short\"\n"));
    ASSERT_TRUE(expect_unchanged("token = \"Enter the token to continue\"\n"));
    ASSERT_TRUE(expect_unchanged("password: \"${DB_PASSWORD_FROM_ENV}\"\n"));
    ASSERT_TRUE(expect_unchanged("secret = os.environ[\"APP_SECRET\"]\n"));
    ASSERT_TRUE(expect_unchanged("assert token == \"abcdefghijklmnop\"\n")); /* '==' */
    ASSERT_TRUE(expect_unchanged("v = \"dGVzdA==\"  // base64 test vector\n"));
    ASSERT_TRUE(expect_unchanged(
        "sha = \"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"\n"));
    ASSERT_TRUE(
        expect_unchanged("css: mask-image: linear; class=\"sk-this-is-a-long-css-name\"\n"));
    ASSERT_TRUE(expect_unchanged("risk-assessment-for-1234567890abcdefghij\n"));
    ASSERT_TRUE(expect_unchanged("// -- section --\n----- BEGIN notes -----\n"));
    ASSERT_TRUE(expect_unchanged("AKIA_PREFIX_IN_NAME\nghp_short\nexample.com/eyJ.eyJ\n"));
    PASS();
}

TEST(redact_env_opt_out_and_inplace) {
    char *text = strdup("password = \"hunter2hunter2xyz\"\n");
    ASSERT_NOT_NULL(text);
    (void)cbm_setenv("CBM_NO_REDACT", "1", 1);
    ASSERT_FALSE(cbm_redact_enabled());
    ASSERT_FALSE(cbm_redact_secrets_inplace(&text));
    ASSERT_NOT_NULL(strstr(text, "hunter2hunter2xyz"));
    (void)cbm_setenv("CBM_NO_REDACT", "0", 1);
    ASSERT_TRUE(cbm_redact_enabled());
    ASSERT_TRUE(cbm_redact_secrets_inplace(&text));
    ASSERT_NULL(strstr(text, "hunter2hunter2xyz"));
    (void)cbm_unsetenv("CBM_NO_REDACT");
    free(text);
    PASS();
}

SUITE(secret_redact) {
    RUN_TEST(redact_aws_access_key);
    RUN_TEST(redact_github_tokens);
    RUN_TEST(redact_openai_and_anthropic_keys);
    RUN_TEST(redact_slack_google_stripe_jwt);
    RUN_TEST(redact_pem_block_keeps_line_count);
    RUN_TEST(redact_pem_without_end_and_windowed_body);
    RUN_TEST(redact_secret_assignments_value_only);
    RUN_TEST(redact_has_no_false_positives_on_normal_code);
    RUN_TEST(redact_env_opt_out_and_inplace);
}
