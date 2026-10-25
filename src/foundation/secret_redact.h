#ifndef CBM_SECRET_REDACT_H
#define CBM_SECRET_REDACT_H

#include <stdbool.h>
#include <stddef.h>

/* Fork hardening: hardcoded secrets inside ordinary source files must never be
 * returned to an AI agent. cbm_redact_secrets() is the single choke point applied
 * to every file text that leaves the server (get_code_snippet source, search_code
 * source/context/raw match lines, UI source views).
 *
 * Detected kinds -> "[REDACTED:<kind>]":
 *   pem-private-key, aws-access-key-id, github-token, anthropic-key, openai-key,
 *   stripe-key, slack-token, google-api-key, jwt, secret-assignment
 *   (password|passwd|secret|token|api_key|... = "<literal of 12+ chars>"; only the
 *   quoted value is replaced).
 *
 * Line structure is preserved: a redaction never removes or adds a newline (a PEM
 * block collapses to one marker followed by the block's original newlines).
 *
 * Debug opt-out: environment variable CBM_NO_REDACT=1. */

/* True unless CBM_NO_REDACT=1. */
bool cbm_redact_enabled(void);

/* Returns a newly malloc'd redacted copy of text (never NULL for non-NULL input
 * except on allocation failure). *changed (optional) is set when anything was
 * redacted. Caller frees. Pure: ignores CBM_NO_REDACT. */
char *cbm_redact_secrets(const char *text, bool *changed);

/* Convenience for output paths: if redaction is enabled and text contained
 * secrets, replaces *text (freeing the old buffer) with the redacted copy and
 * returns true. Otherwise leaves *text untouched and returns false. */
bool cbm_redact_secrets_inplace(char **text);

#endif
