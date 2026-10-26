/* prepare_change.c — one-call edit brief composed from the existing read tools. */
#include "mcp/prepare_change.h"
#include "mcp/compact_out.h"
#include "mcp/mcp.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yyjson/yyjson.h>

enum {
    PC_DEFAULT_BUDGET = 3000,
    PC_MIN_BUDGET = 800,
    PC_MAX_BUDGET = 20000,
    PC_MAX_EXTRA_TERMS = 8,
    PC_NAME_MAX = 512,
    PC_PATH_MAX = 1024,
    PC_ARGS_MAX = 4096,
};

const char CBM_PREPARE_CHANGE_DESCRIPTION[] =
    "Edit brief: source lines, callers, tests, helpers, wiring refs, outline. "
    "create_like copies target.";

const char CBM_PREPARE_CHANGE_SCHEMA[] =
    "{\"type\":\"object\",\"properties\":{\"project\":{\"type\":\"string\"},"
    "\"target\":{\"type\":\"string\"},"
    "\"mode\":{\"type\":\"string\",\"enum\":[\"edit\",\"create_like\"]},"
    "\"also_search\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}},"
    "\"max_output_tokens\":{\"type\":\"integer\"}},"
    "\"required\":[\"project\",\"target\"]}";

typedef struct {
    char qn[PC_PATH_MAX];
    char name[PC_NAME_MAX];
    char label[64];
    char file[PC_PATH_MAX];
    char lines[64];
} pc_symbol_t;

char *cbm_prepare_change_result_text(const char *result_json, int *is_error) {
    if (is_error) {
        *is_error = 1;
    }
    if (!result_json) {
        return NULL;
    }
    yyjson_doc *doc = yyjson_read(result_json, strlen(result_json), 0);
    if (!doc) {
        return NULL;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    if (is_error) {
        *is_error = yyjson_get_bool(yyjson_obj_get(root, "isError")) ? 1 : 0;
    }
    char *out = NULL;
    yyjson_val *first = yyjson_arr_get_first(yyjson_obj_get(root, "content"));
    const char *text = yyjson_get_str(yyjson_obj_get(first, "text"));
    if (text) {
        out = strdup(text);
    }
    yyjson_doc_free(doc);
    return out;
}

/* Appends `s` as a JSON string literal (with quotes). */
static void pc_json_str(cbm_sb_t *sb, const char *s) {
    cbm_sb_append(sb, "\"");
    for (const char *p = s ? s : ""; *p; p++) {
        char esc[8];
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') {
            snprintf(esc, sizeof(esc), "\\%c", c);
            cbm_sb_append(sb, esc);
        } else if (c < 0x20) {
            snprintf(esc, sizeof(esc), "\\u%04x", c);
            cbm_sb_append(sb, esc);
        } else {
            cbm_sb_append_n(sb, p, 1);
        }
    }
    cbm_sb_append(sb, "\"");
}

/* Appends `s` with regex metacharacters escaped, for an exact name_pattern. */
static void pc_regex_literal(cbm_sb_t *sb, const char *s) {
    for (const char *p = s; *p; p++) {
        if (strchr("\\^$.|?*+()[]{}", *p)) {
            cbm_sb_append(sb, "\\");
        }
        cbm_sb_append_n(sb, p, 1);
    }
}

/* Runs one tool and appends its text under a section heading. */
static void pc_section(cbm_sb_t *out, void *srv, cbm_prepare_change_call_fn call,
                       const char *heading, const char *tool, const char *args) {
    cbm_sb_append(out, "\n## ");
    cbm_sb_append(out, heading);
    cbm_sb_append(out, "\n");
    char *result = call(srv, tool, args);
    int is_error = 0;
    char *text = cbm_prepare_change_result_text(result, &is_error);
    free(result);
    if (!text) {
        cbm_sb_append(out, "(unavailable)\n");
        return;
    }
    if (is_error) {
        cbm_sb_append(out, "(skipped: ");
    }
    cbm_sb_append(out, text);
    if (is_error) {
        cbm_sb_append(out, ")");
    }
    size_t len = strlen(text);
    if (len == 0 || text[len - 1] != '\n') {
        cbm_sb_append(out, "\n");
    }
    free(text);
}

static int pc_label_rank(const char *label) {
    static const char *const preferred[] = {"Function", "Method", "Class", "Interface",
                                            "Struct",   "Type",   "Route", NULL};
    for (int i = 0; preferred[i]; i++) {
        if (strcmp(label, preferred[i]) == 0) {
            return i;
        }
    }
    return 100;
}

/* Resolves the target to one symbol via search_graph (json). Prefers an exact
 * qualified-name match, then callable/type labels. */
static bool pc_resolve(void *srv, cbm_prepare_change_call_fn call, const char *project,
                       const char *target, pc_symbol_t *sym) {
    const char *dot = strrchr(target, '.');
    const char *short_name = dot && dot[1] ? dot + 1 : target;

    cbm_sb_t args;
    cbm_sb_init(&args);
    cbm_sb_append(&args, "{\"project\":");
    pc_json_str(&args, project);
    cbm_sb_t pattern;
    cbm_sb_init(&pattern);
    cbm_sb_append(&pattern, "^");
    pc_regex_literal(&pattern, short_name);
    cbm_sb_append(&pattern, "$");
    char *pat = cbm_sb_finish(&pattern);
    cbm_sb_append(&args, ",\"name_pattern\":");
    pc_json_str(&args, pat ? pat : "");
    free(pat);
    cbm_sb_append(&args, ",\"format\":\"json\",\"limit\":25}");
    char *args_json = cbm_sb_finish(&args);
    if (!args_json) {
        return false;
    }
    char *result = call(srv, "search_graph", args_json);
    free(args_json);
    int is_error = 0;
    char *text = cbm_prepare_change_result_text(result, &is_error);
    free(result);
    if (!text || is_error) {
        free(text);
        return false;
    }

    bool found = false;
    int best_rank = 1000;
    yyjson_doc *doc = yyjson_read(text, strlen(text), 0);
    yyjson_val *groups = yyjson_obj_get(yyjson_doc_get_root(doc), "groups");
    size_t gi, gmax;
    yyjson_val *group;
    yyjson_arr_foreach(groups, gi, gmax, group) {
        const char *prefix = yyjson_get_str(yyjson_obj_get(group, "qn_prefix"));
        const char *file = yyjson_get_str(yyjson_obj_get(group, "file"));
        size_t ri, rmax;
        yyjson_val *row;
        yyjson_arr_foreach(yyjson_obj_get(group, "rows"), ri, rmax, row) {
            const char *name = yyjson_get_str(yyjson_arr_get(row, 0));
            const char *label = yyjson_get_str(yyjson_arr_get(row, 1));
            const char *lines = yyjson_get_str(yyjson_arr_get(row, 2));
            if (!name || !label) {
                continue;
            }
            char qn[PC_PATH_MAX];
            snprintf(qn, sizeof(qn), "%s%s%s", prefix && *prefix ? prefix : "",
                     prefix && *prefix ? "." : "", name);
            int rank = pc_label_rank(label);
            if (dot && strcmp(qn, target) == 0) {
                rank = -1;
            }
            if (rank < best_rank) {
                best_rank = rank;
                found = true;
                snprintf(sym->qn, sizeof(sym->qn), "%s", qn);
                snprintf(sym->name, sizeof(sym->name), "%s", name);
                snprintf(sym->label, sizeof(sym->label), "%s", label);
                snprintf(sym->file, sizeof(sym->file), "%s", file ? file : "");
                snprintf(sym->lines, sizeof(sym->lines), "%s", lines ? lines : "");
            }
        }
    }
    yyjson_doc_free(doc);
    free(text);
    return found;
}

/* Builds {"project":P,<key>:V,...rest} into a heap string. */
static char *pc_args(const char *project, const char *key, const char *value, const char *rest) {
    cbm_sb_t sb;
    cbm_sb_init(&sb);
    cbm_sb_append(&sb, "{\"project\":");
    pc_json_str(&sb, project);
    cbm_sb_append(&sb, ",\"");
    cbm_sb_append(&sb, key);
    cbm_sb_append(&sb, "\":");
    pc_json_str(&sb, value);
    if (rest && *rest) {
        cbm_sb_append(&sb, ",");
        cbm_sb_append(&sb, rest);
    }
    cbm_sb_append(&sb, "}");
    return cbm_sb_finish(&sb);
}

static void pc_section_args(cbm_sb_t *out, void *srv, cbm_prepare_change_call_fn call,
                            const char *heading, const char *tool, char *args) {
    if (args) {
        pc_section(out, srv, call, heading, tool, args);
        free(args);
    }
}

char *cbm_prepare_change(void *srv, cbm_prepare_change_call_fn call, const char *args_json) {
    yyjson_doc *doc = args_json ? yyjson_read(args_json, strlen(args_json), 0) : NULL;
    yyjson_val *root = yyjson_doc_get_root(doc);
    const char *project = yyjson_get_str(yyjson_obj_get(root, "project"));
    const char *target = yyjson_get_str(yyjson_obj_get(root, "target"));
    const char *mode = yyjson_get_str(yyjson_obj_get(root, "mode"));
    if (!call || !project || !*project || !target || !*target) {
        yyjson_doc_free(doc);
        return cbm_mcp_text_result("prepare_change requires project and target", true);
    }
    bool create_like = mode && strcmp(mode, "create_like") == 0;
    long budget = PC_DEFAULT_BUDGET;
    yyjson_val *budget_val = yyjson_obj_get(root, "max_output_tokens");
    if (yyjson_is_int(budget_val)) {
        budget = (long)yyjson_get_sint(budget_val);
    }
    if (budget < PC_MIN_BUDGET) {
        budget = PC_MIN_BUDGET;
    }
    if (budget > PC_MAX_BUDGET) {
        budget = PC_MAX_BUDGET;
    }

    pc_symbol_t sym;
    memset(&sym, 0, sizeof(sym));
    if (!pc_resolve(srv, call, project, target, &sym)) {
        char message[PC_PATH_MAX];
        snprintf(message, sizeof(message),
                 "prepare_change: no indexed symbol named '%s' in project '%s'. Try "
                 "search_graph with a partial name_pattern, or index_repository first.",
                 target, project);
        yyjson_doc_free(doc);
        return cbm_mcp_text_result(message, true);
    }

    cbm_sb_t out;
    cbm_sb_init(&out);
    cbm_sb_append(&out, create_like ? "# prepare_change (create_like): copy this example\n"
                                    : "# prepare_change (edit)\n");
    char line[PC_PATH_MAX * 2];
    snprintf(line, sizeof(line), "target: %s\nlabel: %s\nfile: %s\nlines: %s\n", sym.qn, sym.label,
             sym.file, sym.lines);
    cbm_sb_append(&out, line);

    /* Budget split: source gets the largest share; graph tables are compact. */
    char rest[PC_ARGS_MAX];
    snprintf(rest, sizeof(rest), "\"max_output_tokens\":%ld",
             budget * 45 / 100 < 128 ? 128 : budget * 45 / 100);
    pc_section_args(&out, srv, call,
                    "SOURCE (exact lines; edit these, no need to re-read the file)",
                    "get_code_snippet", pc_args(project, "qualified_name", sym.qn, rest));

    snprintf(rest, sizeof(rest),
             "\"direction\":\"inbound\",\"depth\":1,\"include_tests\":true,\"limit\":30,"
             "\"max_output_tokens\":%ld",
             budget * 15 / 100 < 128 ? 128 : budget * 15 / 100);
    pc_section_args(&out, srv, call,
                    create_like ? "CALLERS OF THE EXAMPLE (a new sibling usually needs the same "
                                  "call sites)"
                                : "CALLERS (keep these working if the signature changes; test "
                                  "callers = tests to re-run)",
                    "trace_path", pc_args(project, "function_name", sym.qn, rest));

    snprintf(rest, sizeof(rest),
             "\"direction\":\"outbound\",\"depth\":1,\"limit\":20,\"max_output_tokens\":%ld",
             budget * 10 / 100 < 128 ? 128 : budget * 10 / 100);
    pc_section_args(&out, srv, call, "USES (reuse these helpers instead of writing new ones)",
                    "trace_path", pc_args(project, "function_name", sym.qn, rest));

    pc_section_args(&out, srv, call,
                    "TEXT REFERENCES (wiring: imports, exports, routes, registries, configs)",
                    "search_code", pc_args(project, "pattern", sym.name, "\"limit\":15"));

    yyjson_val *extra = yyjson_obj_get(root, "also_search");
    size_t xi, xmax;
    yyjson_val *term;
    yyjson_arr_foreach(extra, xi, xmax, term) {
        const char *s = yyjson_get_str(term);
        if (!s || !*s || xi >= PC_MAX_EXTRA_TERMS) {
            continue;
        }
        char heading[PC_NAME_MAX];
        snprintf(heading, sizeof(heading), "REFERENCES TO \"%.200s\"", s);
        pc_section_args(&out, srv, call, heading, "search_code",
                        pc_args(project, "pattern", s, "\"limit\":15"));
    }

    if (sym.file[0]) {
        pc_section_args(&out, srv, call, "FILE OUTLINE (where neighbours live; keep this order)",
                        "get_file_outline",
                        pc_args(project, "file_path", sym.file, "\"limit\":60"));
    }

    cbm_sb_append(&out, create_like
                            ? "\n## NEXT\n1. Create the new symbol beside the example, following "
                              "its shape and helpers.\n2. Add it at every wiring reference "
                              "above that the example appears in.\n3. Run detect_changes to "
                              "confirm the blast radius, then the listed tests.\n"
                            : "\n## NEXT\n1. Edit the lines shown in SOURCE.\n2. Update every "
                              "caller above if the signature or behaviour changed.\n3. Run "
                              "detect_changes to confirm the blast radius, then the listed "
                              "tests.\n");
    yyjson_doc_free(doc);
    char *text = cbm_sb_finish(&out);
    if (!text) {
        return cbm_mcp_text_result("prepare_change: out of memory", true);
    }
    char *result = cbm_mcp_text_result(text, false);
    free(text);
    return result;
}
