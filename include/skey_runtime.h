#ifndef SKEY_RUNTIME_H
#define SKEY_RUNTIME_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#define SKEY_EXPORT __declspec(dllexport)
#else
#define SKEY_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct skey_context skey_context;

typedef enum skey_status {
    SKEY_OK = 0,
    E_LICENSE_MISSING = -1001,
    E_LICENSE_SIGNATURE = -1002,
    E_MACHINE_MISMATCH = -1003,
    E_LICENSE_EXPIRED = -1004,
    E_LEASE_EXPIRED = -1005,
    E_CLOCK_ROLLBACK = -1006,
    E_FEATURE_DENIED = -1007,
    E_PACKAGE_TAMPERED = -1008,
    E_DECRYPT_FAILED = -1009,
    E_SESSION_INVALID = -1010,
    E_PROCESS_LAUNCH = -1011,
    E_INVALID_ARGUMENT = -1100,
    E_INTERNAL = -1999
} skey_status;

typedef struct skey_init_options {
    const char *app_root;
    const char *payload_path;
    const char *entry_id;
    const char *original_path;
    const char *argv_json;
    const char *env_session;
} skey_init_options;

typedef struct skey_buffer {
    uint8_t *data;
    size_t len;
} skey_buffer;

/*
 * Runtime lifecycle:
 * - skey_runtime_init validates required strings, loads the SKP payload, and
 *   verifies the signed package manifest using .secure/runtime.manifest.public-key.json.
 * - Production runtime builds must embed SKEY_VENDOR_PUBLIC_KEY_SHA256 so the
 *   mutable public-key sidecar is pinned to the vendor signing key.
 * - activation.cert is not required during init. Missing or invalid license
 *   material is reported by skey_license_check or decrypting load calls.
 * - Calls that use the same skey_context are internally serialized.
 *
 * Last error ownership:
 * - skey_last_error_message returns a thread-local pointer that remains valid
 *   until the next SKey call on the same thread updates the last error message.
 * - Do not free the returned pointer.
 *
 * Buffer ownership:
 * - Non-empty buffers returned by SKey must be released exactly once with
 *   skey_buffer_free.
 * - Returned buffer data must not be passed to free or any other allocator.
 * - Null/zero buffers are valid and safe to pass to skey_buffer_free.
 *
 * Resource handles:
 * - skey_resource_open accepts either a manifest resource id such as
 *   "res:data/model.dat" or the original path "data/model.dat".
 * - skey_resource_read returns a newly allocated buffer for the requested byte
 *   range and decrypts only the chunks needed for chunked resource blobs.
 * - Every successful resource handle must be closed with skey_resource_close.
 * - Closing a context invalidates any resource handles opened from that context.
 */
SKEY_EXPORT skey_status skey_runtime_init(const skey_init_options *options, skey_context **out_ctx);
SKEY_EXPORT skey_status skey_license_check(skey_context *ctx, const char *feature_code);
SKEY_EXPORT skey_status skey_load_entry(skey_context *ctx, const char *entry_id, skey_buffer *out_source);
SKEY_EXPORT skey_status skey_find_module(skey_context *ctx, const char *module_name, skey_buffer *out_json);
SKEY_EXPORT skey_status skey_load_module(skey_context *ctx, const char *module_name, skey_buffer *out_source);
SKEY_EXPORT skey_status skey_materialize_entry(skey_context *ctx, const char *entry_id, skey_buffer *out_bytes);
SKEY_EXPORT skey_status skey_create_session(skey_context *ctx, skey_buffer *out_token);
SKEY_EXPORT skey_status skey_resource_open(skey_context *ctx, const char *resource_id, uint64_t *out_handle);
SKEY_EXPORT skey_status skey_resource_read(uint64_t handle, uint64_t offset, size_t len, skey_buffer *out_bytes);
SKEY_EXPORT void skey_resource_close(uint64_t handle);
SKEY_EXPORT const char *skey_last_error_message(void);
SKEY_EXPORT void skey_buffer_free(skey_buffer buffer);
SKEY_EXPORT void skey_context_free(skey_context *ctx);

#ifdef __cplusplus
}
#endif

#endif
