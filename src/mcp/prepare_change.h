/* prepare_change.h — one-call edit brief for "change / create / refactor" tasks.
 *
 * Read tools answer "where" and "how"; an agent asked to *make* a change still
 * spends several round trips collecting the same context: the exact source and
 * line range, the helpers it should reuse, every caller it must keep working,
 * the tests to re-run and the text references (routes, exports, registries,
 * configs) that wire a symbol into the app. prepare_change composes the
 * existing read tools into that single bounded brief. It never writes files.
 */
#ifndef CBM_MCP_PREPARE_CHANGE_H
#define CBM_MCP_PREPARE_CHANGE_H

/* Calls one existing tool by name inside the current request; returns an MCP
 * tool result JSON string (caller frees). */
typedef char *(*cbm_prepare_change_call_fn)(void *srv, const char *tool_name,
                                            const char *args_json);

/* Tool schema pieces, registered next to the built-in tools. */
extern const char CBM_PREPARE_CHANGE_DESCRIPTION[];
extern const char CBM_PREPARE_CHANGE_SCHEMA[];

/* Builds the brief and returns an MCP tool result JSON string (caller frees). */
char *cbm_prepare_change(void *srv, cbm_prepare_change_call_fn call, const char *args_json);

/* Exposed for tests: the plain-text text item of an MCP tool result, or NULL.
 * *is_error receives the result's isError flag. Caller frees. */
char *cbm_prepare_change_result_text(const char *result_json, int *is_error);

#endif /* CBM_MCP_PREPARE_CHANGE_H */
