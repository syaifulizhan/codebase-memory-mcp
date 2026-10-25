/* prepare_change: one-call edit brief composed from read tools (fork addition). */
#include "test_framework.h"

#include "mcp/mcp.h"
#include "mcp/prepare_change.h"

#include <stdlib.h>
#include <string.h>

static int g_calls;

/* Fake tool backend: search_graph resolves one function; others echo their name. */
static char *fake_call(void *srv, const char *tool, const char *args) {
    (void)srv;
    g_calls++;
    if (strcmp(tool, "search_graph") == 0) {
        if (strstr(args, "missing")) {
            return cbm_mcp_text_result("{\"groups\":[],\"total\":0}", false);
        }
        return cbm_mcp_text_result(
            "{\"groups\":[{\"qn_prefix\":\"p.src.lib\",\"file\":\"src/lib.ts\",\"rows\":["
            "[\"save\",\"Variable\",\"1-1\",0,0],[\"save\",\"Function\",\"8-14\",3,1]]}]}",
            false);
    }
    if (strcmp(tool, "search_code") == 0) {
        return cbm_mcp_text_result("search failed", true);
    }
    return cbm_mcp_text_result(tool, false);
}

static char *brief(const char *args) {
    char *result = cbm_prepare_change(NULL, fake_call, args);
    int is_error = 0;
    char *text = cbm_prepare_change_result_text(result, &is_error);
    free(result);
    if (text && is_error) {
        char *marked = malloc(strlen(text) + 8);
        if (marked) {
            strcpy(marked, "ERROR: ");
            strcat(marked, text);
        }
        free(text);
        return marked;
    }
    return text;
}

TEST(prepare_change_edit_brief) {
    g_calls = 0;
    char *text = brief("{\"project\":\"p\",\"target\":\"save\"}");
    ASSERT_NOT_NULL(text);
    ASSERT_TRUE(strstr(text, "target: p.src.lib.save") != NULL);
    ASSERT_TRUE(strstr(text, "label: Function") != NULL);
    ASSERT_TRUE(strstr(text, "file: src/lib.ts") != NULL);
    ASSERT_TRUE(strstr(text, "get_code_snippet") != NULL);
    ASSERT_TRUE(strstr(text, "trace_path") != NULL);
    ASSERT_TRUE(strstr(text, "get_file_outline") != NULL);
    ASSERT_TRUE(strstr(text, "(skipped: search failed)") != NULL);
    ASSERT_TRUE(strstr(text, "## NEXT") != NULL);
    ASSERT_EQ(g_calls, 6);
    free(text);
    PASS();
}

TEST(prepare_change_create_like_and_extra_terms) {
    g_calls = 0;
    char *text = brief("{\"project\":\"p\",\"target\":\"save\",\"mode\":\"create_like\","
                       "\"also_search\":[\"/api/save\"]}");
    ASSERT_NOT_NULL(text);
    ASSERT_TRUE(strstr(text, "create_like") != NULL);
    ASSERT_TRUE(strstr(text, "REFERENCES TO \"/api/save\"") != NULL);
    ASSERT_EQ(g_calls, 7);
    free(text);
    PASS();
}

TEST(prepare_change_errors) {
    char *text = brief("{\"project\":\"p\"}");
    ASSERT_NOT_NULL(text);
    ASSERT_TRUE(strncmp(text, "ERROR: ", 7) == 0);
    free(text);
    text = brief("{\"project\":\"p\",\"target\":\"missing\"}");
    ASSERT_NOT_NULL(text);
    ASSERT_TRUE(strstr(text, "no indexed symbol") != NULL);
    free(text);
    PASS();
}

SUITE(prepare_change) {
    RUN_TEST(prepare_change_edit_brief);
    RUN_TEST(prepare_change_create_like_and_extra_terms);
    RUN_TEST(prepare_change_errors);
}
