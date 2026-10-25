/* Secret-content redaction (fork hardening). Hand-written scanners, one linear
 * pass, no regex library. See secret_redact.h for the contract. */
#include "foundation/secret_redact.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    AWS_KEY_LEN = 20,
    AWS_KEY_TAIL = 16,
    GOOGLE_KEY_TAIL = 35,
    GITHUB_TOKEN_MIN = 36,
    GITHUB_PAT_MIN = 22,
    ANTHROPIC_MIN = 20,
    OPENAI_MIN = 20,
    STRIPE_MIN = 16,
    SLACK_MIN = 10,
    JWT_SEGMENT_MIN = 7,
    PEM_HEADER_SCAN = 48,
    B64_LINE_MIN = 48,
    ASSIGN_VALUE_MIN = 12,
    ASSIGN_VALUE_MAX = 512,
    ASSIGN_IDENT_MAX = 48,
    MARKER_CAP = 48,
    GROW_SLACK = 64,
    PREFIX_4 = 4,
    PREFIX_3 = 3,
};

typedef struct {
    size_t skip;       /* bytes from the scan position to the first redacted byte */
    size_t len;        /* redacted byte count */
    const char *kind;  /* marker kind */
    bool keep_newline; /* PEM: re-emit the block's newlines after the marker */
} hit_t;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} out_t;

static bool out_put(out_t *out, const char *s, size_t n) {
    if (out->len + n + 1 > out->cap) {
        size_t cap = (out->cap ? out->cap : GROW_SLACK) * 2;
        while (cap < out->len + n + 1) {
            cap *= 2;
        }
        char *grown = realloc(out->data, cap);
        if (!grown) {
            return false;
        }
        out->data = grown;
        out->cap = cap;
    }
    memcpy(out->data + out->len, s, n);
    out->len += n;
    out->data[out->len] = '\0';
    return true;
}

static bool is_alnum(char c) {
    return isalnum((unsigned char)c) != 0;
}

static bool is_word(char c) {
    return is_alnum(c) || c == '_';
}

static bool is_b64url(char c) {
    return is_alnum(c) || c == '-' || c == '_';
}

static size_t run_alnum(const char *s, size_t avail) {
    size_t n = 0;
    while (n < avail && is_alnum(s[n])) {
        n++;
    }
    return n;
}

static size_t run_b64url(const char *s, size_t avail) {
    size_t n = 0;
    while (n < avail && is_b64url(s[n])) {
        n++;
    }
    return n;
}

static bool starts_with(const char *s, size_t avail, const char *prefix) {
    size_t n = strlen(prefix);
    return avail >= n && memcmp(s, prefix, n) == 0;
}

static bool run_has_digit(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (isdigit((unsigned char)s[i])) {
            return true;
        }
    }
    return false;
}

/* ── token-shaped secrets (anchored at a word boundary) ───────── */

static bool match_aws(const char *s, size_t avail, hit_t *hit) {
    static const char *const prefixes[] = {"AKIA", "ASIA", "AGPA", "AIDA",
                                           "AROA", "ANPA", "ANVA", "AIPA"};
    if (avail < AWS_KEY_LEN) {
        return false;
    }
    bool known = false;
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        known = known || memcmp(s, prefixes[i], PREFIX_4) == 0;
    }
    if (!known) {
        return false;
    }
    for (size_t i = PREFIX_4; i < AWS_KEY_LEN; i++) {
        if (!(isupper((unsigned char)s[i]) || isdigit((unsigned char)s[i]))) {
            return false;
        }
    }
    if (avail > AWS_KEY_LEN && is_alnum(s[AWS_KEY_LEN])) {
        return false;
    }
    *hit = (hit_t){0, AWS_KEY_LEN, "aws-access-key-id", false};
    return true;
}

static bool match_google(const char *s, size_t avail, hit_t *hit) {
    if (!starts_with(s, avail, "AIza") || avail < PREFIX_4 + GOOGLE_KEY_TAIL) {
        return false;
    }
    if (run_b64url(s + PREFIX_4, avail - PREFIX_4) < GOOGLE_KEY_TAIL) {
        return false;
    }
    *hit = (hit_t){0, PREFIX_4 + GOOGLE_KEY_TAIL, "google-api-key", false};
    return true;
}

static bool match_github(const char *s, size_t avail, hit_t *hit) {
    if (starts_with(s, avail, "github_pat_")) {
        size_t n = run_b64url(s + strlen("github_pat_"), avail - strlen("github_pat_"));
        if (n >= GITHUB_PAT_MIN) {
            *hit = (hit_t){0, strlen("github_pat_") + n, "github-token", false};
            return true;
        }
        return false;
    }
    if (avail > PREFIX_4 && s[0] == 'g' && s[1] == 'h' && strchr("pousr", s[2]) && s[3] == '_') {
        size_t n = run_alnum(s + PREFIX_4, avail - PREFIX_4);
        if (n >= GITHUB_TOKEN_MIN) {
            *hit = (hit_t){0, PREFIX_4 + n, "github-token", false};
            return true;
        }
    }
    return false;
}

static bool match_sk(const char *s, size_t avail, hit_t *hit) {
    if (starts_with(s, avail, "sk_live_") || starts_with(s, avail, "rk_live_")) {
        size_t n = run_alnum(s + strlen("sk_live_"), avail - strlen("sk_live_"));
        if (n >= STRIPE_MIN) {
            *hit = (hit_t){0, strlen("sk_live_") + n, "stripe-key", false};
            return true;
        }
        return false;
    }
    if (starts_with(s, avail, "sk-ant-")) {
        size_t n = run_b64url(s + strlen("sk-ant-"), avail - strlen("sk-ant-"));
        if (n >= ANTHROPIC_MIN) {
            *hit = (hit_t){0, strlen("sk-ant-") + n, "anthropic-key", false};
            return true;
        }
        return false;
    }
    if (starts_with(s, avail, "sk-")) {
        size_t n = run_b64url(s + PREFIX_3, avail - PREFIX_3);
        /* A digit keeps hyphenated English identifiers ("sk-this-is-a-class") out. */
        if (n >= OPENAI_MIN && run_has_digit(s + PREFIX_3, n)) {
            *hit = (hit_t){0, PREFIX_3 + n, "openai-key", false};
            return true;
        }
    }
    return false;
}

static bool match_slack(const char *s, size_t avail, hit_t *hit) {
    if (avail < PREFIX_4 + SLACK_MIN || memcmp(s, "xox", PREFIX_3) != 0 || !strchr("abpr", s[3]) ||
        s[PREFIX_4] != '-') {
        return false;
    }
    size_t n = 0;
    const char *tail = s + PREFIX_4 + 1;
    size_t room = avail - PREFIX_4 - 1;
    while (n < room && (is_alnum(tail[n]) || tail[n] == '-')) {
        n++;
    }
    if (n < SLACK_MIN) {
        return false;
    }
    *hit = (hit_t){0, PREFIX_4 + 1 + n, "slack-token", false};
    return true;
}

static bool match_jwt(const char *s, size_t avail, hit_t *hit) {
    if (!starts_with(s, avail, "eyJ")) {
        return false;
    }
    size_t pos = PREFIX_3;
    size_t a = run_b64url(s + pos, avail - pos);
    pos += a;
    if (a < JWT_SEGMENT_MIN || pos >= avail || s[pos] != '.') {
        return false;
    }
    pos++;
    if (!starts_with(s + pos, avail - pos, "eyJ")) {
        return false;
    }
    pos += PREFIX_3;
    size_t b = run_b64url(s + pos, avail - pos);
    pos += b;
    if (b < JWT_SEGMENT_MIN || pos >= avail || s[pos] != '.') {
        return false;
    }
    pos++;
    pos += run_b64url(s + pos, avail - pos);
    *hit = (hit_t){0, pos, "jwt", false};
    return true;
}

/* -----BEGIN [X ]PRIVATE KEY[ BLOCK]----- ... -----END ...PRIVATE KEY[ BLOCK]-----
 * A block with no END (a windowed read that cut it) is redacted to the end. */
static bool match_pem(const char *s, size_t avail, hit_t *hit) {
    static const char begin[] = "-----BEGIN ";
    if (!starts_with(s, avail, begin)) {
        return false;
    }
    size_t scan = avail - strlen(begin) < PEM_HEADER_SCAN ? avail - strlen(begin) : PEM_HEADER_SCAN;
    const char *label = s + strlen(begin);
    size_t pk = 0;
    bool found = false;
    for (; pk + strlen("PRIVATE KEY") <= scan; pk++) {
        if (label[pk] == '\n' || label[pk] == '-') {
            break;
        }
        if (memcmp(label + pk, "PRIVATE KEY", strlen("PRIVATE KEY")) == 0) {
            found = true;
            break;
        }
    }
    if (!found) {
        return false;
    }
    size_t end_of_label = strlen(begin) + pk + strlen("PRIVATE KEY");
    const char *rest = s + end_of_label;
    size_t rest_len = avail - end_of_label;
    if (starts_with(rest, rest_len, " BLOCK")) {
        rest += strlen(" BLOCK");
        rest_len -= strlen(" BLOCK");
        end_of_label += strlen(" BLOCK");
    }
    if (!starts_with(rest, rest_len, "-----")) {
        return false;
    }
    size_t body = end_of_label + strlen("-----");
    size_t total = avail;
    for (size_t i = body; i + strlen("-----END ") <= avail; i++) {
        if (s[i] == '-' && memcmp(s + i, "-----END ", strlen("-----END ")) == 0) {
            size_t j = i + strlen("-----END ");
            const char *close = NULL;
            while (j + strlen("-----") <= avail && s[j] != '\n') {
                if (s[j] == '-' && memcmp(s + j, "-----", strlen("-----")) == 0) {
                    close = s + j;
                    break;
                }
                j++;
            }
            if (close) {
                total = (size_t)(close - s) + strlen("-----");
                break;
            }
        }
    }
    *hit = (hit_t){0, total, "pem-private-key", true};
    return true;
}

/* A bare line of base64 (>= 48 chars, mixed case): the body of a PEM block whose
 * BEGIN line fell outside a windowed read. Mixed case keeps hex digests out. */
static bool match_base64_line(const char *s, size_t avail, hit_t *hit) {
    size_t n = 0;
    bool upper = false;
    bool lower = false;
    while (n < avail && (is_alnum(s[n]) || s[n] == '+' || s[n] == '/' || s[n] == '=')) {
        upper = upper || isupper((unsigned char)s[n]);
        lower = lower || islower((unsigned char)s[n]);
        n++;
    }
    if (n < B64_LINE_MIN || !upper || !lower) {
        return false;
    }
    if (n < avail && s[n] != '\n' && s[n] != '\r') {
        return false;
    }
    *hit = (hit_t){0, n, "pem-body", false};
    return true;
}

/* ── <name> = "<literal>" assignments ─────────────────────────── */

static bool ident_has_secret_suffix(const char *ident, size_t n) {
    static const char *const suffixes[] = {"password",  "passwd",     "secret",     "token",
                                           "api_key",   "apikey",     "api-key",    "secret_key",
                                           "secretkey", "access_key", "private_key"};
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        size_t sl = strlen(suffixes[i]);
        if (n >= sl) {
            size_t k = 0;
            while (k < sl &&
                   tolower((unsigned char)ident[n - sl + k]) == (unsigned char)suffixes[i][k]) {
                k++;
            }
            if (k == sl) {
                return true;
            }
        }
    }
    return false;
}

static bool value_is_placeholder(const char *v, size_t n) {
    static const char *const skip[] = {"${", "{{", "<", "%(", "$(", "process.env", "os.environ"};
    for (size_t i = 0; i < sizeof(skip) / sizeof(skip[0]); i++) {
        if (starts_with(v, n, skip[i])) {
            return true;
        }
    }
    for (size_t i = 0; i < n; i++) {
        if (v[i] == ' ' || v[i] == '\t') {
            return true; /* prose/labels, not a credential literal */
        }
    }
    return false;
}

/* Triggered at '=' or ':'. text/at give the whole buffer for the backward look. */
static bool match_assignment(const char *text, size_t at, size_t len, hit_t *hit) {
    size_t after = at + 1;
    if (text[at] == ':' && after < len && text[after] == '=') {
        after++;
    } else if (text[at] == '=' && after < len && text[after] == '>') {
        after++;
    } else if (text[at] == '=' && after < len && text[after] == '=') {
        return false;
    }
    size_t k = at;
    while (k > 0 && (text[k - 1] == ' ' || text[k - 1] == '\t')) {
        k--;
    }
    if (k > 0 && (text[k - 1] == '"' || text[k - 1] == '\'' || text[k - 1] == '`')) {
        k--;
    }
    size_t ident_end = k;
    while (k > 0 && ident_end - k < ASSIGN_IDENT_MAX &&
           (is_alnum(text[k - 1]) || text[k - 1] == '_' || text[k - 1] == '-')) {
        k--;
    }
    if (ident_end == k || !ident_has_secret_suffix(text + k, ident_end - k)) {
        return false;
    }
    size_t p = after;
    while (p < len && (text[p] == ' ' || text[p] == '\t')) {
        p++;
    }
    if (p >= len || (text[p] != '"' && text[p] != '\'' && text[p] != '`')) {
        return false;
    }
    char quote = text[p];
    size_t vstart = p + 1;
    size_t v = vstart;
    while (v < len && text[v] != quote && text[v] != '\n' && v - vstart <= ASSIGN_VALUE_MAX) {
        if (text[v] == '\\' && v + 1 < len && text[v + 1] != '\n') {
            v++;
        }
        v++;
    }
    if (v >= len || text[v] != quote) {
        return false;
    }
    size_t vlen = v - vstart;
    if (vlen < ASSIGN_VALUE_MIN || vlen > ASSIGN_VALUE_MAX ||
        value_is_placeholder(text + vstart, vlen)) {
        return false;
    }
    *hit = (hit_t){vstart - at, vlen, "secret-assignment", false};
    return true;
}

static bool match_at(const char *text, size_t i, size_t len, hit_t *hit) {
    const char *s = text + i;
    size_t avail = len - i;
    bool boundary = i == 0 || !is_word(text[i - 1]);
    char c = *s;
    if (c == '=' || c == ':') {
        return match_assignment(text, i, len, hit);
    }
    if (c == '-' && (i == 0 || text[i - 1] != '-')) {
        return match_pem(s, avail, hit);
    }
    if (boundary) {
        bool found = false;
        switch (c) {
        case 'A':
            found = match_aws(s, avail, hit) || match_google(s, avail, hit);
            break;
        case 'g':
            found = match_github(s, avail, hit);
            break;
        case 's':
        case 'r':
            found = match_sk(s, avail, hit);
            break;
        case 'x':
            found = match_slack(s, avail, hit);
            break;
        case 'e':
            found = match_jwt(s, avail, hit);
            break;
        default:
            break;
        }
        if (found) {
            return true;
        }
    }
    if ((i == 0 || text[i - 1] == '\n') && (is_alnum(c) || c == '+' || c == '/')) {
        return match_base64_line(s, avail, hit);
    }
    return false;
}

bool cbm_redact_enabled(void) {
    const char *off = getenv("CBM_NO_REDACT");
    return !(off && strcmp(off, "1") == 0);
}

char *cbm_redact_secrets(const char *text, bool *changed) {
    if (changed) {
        *changed = false;
    }
    if (!text) {
        return NULL;
    }
    size_t len = strlen(text);
    out_t out = {0};
    size_t copied = 0;
    size_t i = 0;
    bool any = false;
    while (i < len) {
        hit_t hit;
        if (!match_at(text, i, len, &hit)) {
            i++;
            continue;
        }
        size_t from = i + hit.skip;
        char marker[MARKER_CAP];
        int mlen = snprintf(marker, sizeof(marker), "[REDACTED:%s]", hit.kind);
        if (!out_put(&out, text + copied, from - copied) || !out_put(&out, marker, (size_t)mlen)) {
            free(out.data);
            return NULL;
        }
        if (hit.keep_newline) {
            for (size_t k = from; k < from + hit.len; k++) {
                if (text[k] == '\n' && !out_put(&out, "\n", 1)) {
                    free(out.data);
                    return NULL;
                }
            }
        }
        copied = from + hit.len;
        i = copied;
        any = true;
    }
    if (!any) {
        char *same = malloc(len + 1);
        if (same) {
            memcpy(same, text, len + 1);
        }
        return same;
    }
    if (!out_put(&out, text + copied, len - copied)) {
        free(out.data);
        return NULL;
    }
    if (changed) {
        *changed = true;
    }
    return out.data;
}

bool cbm_redact_secrets_inplace(char **text) {
    if (!text || !*text || !cbm_redact_enabled()) {
        return false;
    }
    bool changed = false;
    char *redacted = cbm_redact_secrets(*text, &changed);
    if (!redacted || !changed) {
        free(redacted);
        return false;
    }
    free(*text);
    *text = redacted;
    return true;
}
