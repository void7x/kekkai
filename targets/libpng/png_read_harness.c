#include <png.h>

#include <limits.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(PNG_READ_SUPPORTED) || \
    !defined(PNG_SEQUENTIAL_READ_SUPPORTED) || \
    !defined(PNG_READ_ANCILLARY_CHUNKS_SUPPORTED) || \
    !defined(PNG_READ_INTERLACING_SUPPORTED) || \
    !defined(PNG_SETJMP_SUPPORTED) || \
    !defined(PNG_SET_USER_LIMITS_SUPPORTED)
#error "The selected libpng build lacks a required harness feature"
#endif

#define MAX_INPUT_BYTES (8U * 1024U * 1024U)
#define MAX_IMAGE_WIDTH 8192U
#define MAX_IMAGE_HEIGHT 8192U
#define MAX_TOTAL_PIXELS 16000000U
#define MAX_ROW_BYTES (64U * 1024U)
#define MAX_CHUNK_BYTES (256U * 1024U)
#define MAX_CACHED_CHUNKS 128U
#define MESSAGE_CAPACITY 160U

typedef struct harness_context {
    unsigned char *input;
    size_t input_size;
    size_t input_offset;

    png_structp png_ptr;
    png_infop info_ptr;
    png_infop end_info_ptr;

    char error_message[MESSAGE_CAPACITY];
    char warning_message[MESSAGE_CAPACITY];
    unsigned int warning_count;

    int harness_failure;
} harness_context;

static void store_message(char *destination, size_t capacity,
                          const char *message)
{
    if (capacity == 0U)
        return;

    if (message == NULL)
        message = "(no diagnostic message)";

    (void)snprintf(destination, capacity, "%s", message);
}

static int is_libpng_allocation_failure(const char *message)
{
    if (message == NULL)
        return 0;

    /*
     * libpng 1.6.59 reports allocation failures through several paths:
     * direct allocation errors, chunk errors and Z_MEM_ERROR.
     * Chunk errors may prefix the message with the chunk name.
     *
     * This function is called only by the fatal error callback.
     * Non-fatal chunk warnings use the separate warning callback.
     */
    return strstr(message, "out of memory") != NULL ||
           strstr(message, "Out of memory") != NULL ||
           strstr(message, "Out of Memory") != NULL ||
           strstr(message, "insufficient memory") != NULL ||
           strstr(message, "Insufficient memory") != NULL ||
           strstr(message, "Insufficient Memory") != NULL;
}

static void png_error_callback(png_structp png_ptr,
                               png_const_charp message)
{
    harness_context *context =
        (harness_context *)png_get_error_ptr(png_ptr);

    if (context == NULL)
        abort();

    /*
     * libpng 1.6.59 uses these exact messages for fatal allocation failures.
     */
    if (is_libpng_allocation_failure(message))
        context->harness_failure = 1;

    store_message(context->error_message,
                  sizeof(context->error_message), message);

    /*
     * Do not return from a fatal libpng error callback.
     * The caller establishes png_jmpbuf() before parser operations.
     */
    png_longjmp(png_ptr, 1);
    abort();
}

static void png_warning_callback(png_structp png_ptr,
                                 png_const_charp message)
{
    harness_context *context =
        (harness_context *)png_get_error_ptr(png_ptr);

    if (context == NULL)
        return;

    if (context->warning_count < UINT_MAX)
        context->warning_count++;

    if (context->warning_message[0] == '\0') {
        store_message(context->warning_message,
                      sizeof(context->warning_message), message);
    }
}

static void png_memory_read(png_structp png_ptr,
                            png_bytep output,
                            png_size_t requested)
{
    harness_context *context =
        (harness_context *)png_get_io_ptr(png_ptr);

    if (context == NULL) {
        png_error(png_ptr, "missing input context");
        abort();
    }

    if (context->input_offset > context->input_size) {
        png_error(png_ptr, "invalid input cursor");
        abort();
    }

    size_t remaining = context->input_size - context->input_offset;

    if ((size_t)requested > remaining) {
        png_error(png_ptr, "truncated input: read exceeds remaining bytes");
        abort();
    }

    if (requested > 0U) {
        memcpy(output, context->input + context->input_offset,
               (size_t)requested);
        context->input_offset += (size_t)requested;
    }
}

/*
 * Return values:
 *   0: input loaded
 *   1: input exceeds the approved size limit
 *   2: file or allocation error
 */
static int load_input_file(harness_context *context, const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
        return 2;

    if (fseek(file, 0L, SEEK_END) != 0) {
        (void)fclose(file);
        return 2;
    }

    long file_length = ftell(file);
    if (file_length < 0L) {
        (void)fclose(file);
        return 2;
    }

    if ((unsigned long)file_length > (unsigned long)MAX_INPUT_BYTES) {
        (void)fclose(file);
        return 1;
    }

    if (fseek(file, 0L, SEEK_SET) != 0) {
        (void)fclose(file);
        return 2;
    }

    context->input_size = (size_t)file_length;

    /* Allocate one byte for an empty file so the pointer remains owned. */
    size_t allocation_size =
        context->input_size == 0U ? 1U : context->input_size;

    context->input = (unsigned char *)malloc(allocation_size);
    if (context->input == NULL) {
        (void)fclose(file);
        return 2;
    }

    if (context->input_size > 0U) {
        size_t bytes_read = fread(context->input, 1U,
                                  context->input_size, file);

        if (bytes_read != context->input_size || ferror(file)) {
            (void)fclose(file);
            return 2;
        }
    }

    if (fclose(file) != 0)
        return 2;

    return 0;
}

static void cleanup_context(harness_context *context)
{
    if (context->png_ptr != NULL) {
        png_destroy_read_struct(
            &context->png_ptr,
            context->info_ptr != NULL ? &context->info_ptr : NULL,
            context->end_info_ptr != NULL ? &context->end_info_ptr : NULL);
    }

    free(context->input);
    context->input = NULL;
}

static void report_diagnostics(const harness_context *context)
{
    const char *enabled = getenv("KEKKAI_HARNESS_DIAGNOSTICS");

    if (enabled == NULL || enabled[0] == '\0' ||
        strcmp(enabled, "0") == 0)
        return;

    if (context->error_message[0] != '\0')
        (void)fprintf(stderr, "libpng error: %s\n",
                      context->error_message);

    if (context->warning_count > 0U) {
        (void)fprintf(stderr, "libpng warnings: %u\n",
                      context->warning_count);

        if (context->warning_message[0] != '\0')
            (void)fprintf(stderr, "first warning: %s\n",
                          context->warning_message);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;

    /*
     * The context lives on the heap. Its mutable cleanup state remains
     * well-defined after longjmp. Do not reassign this local context pointer
     * after establishing setjmp().
     */
    harness_context *context =
        (harness_context *)calloc(1U, sizeof(*context));

    if (context == NULL)
        return 2;

    int input_status = load_input_file(context, argv[1]);

    if (input_status != 0) {
        if (input_status == 1) {
            store_message(context->error_message,
                          sizeof(context->error_message),
                          "input exceeds the 8 MiB limit");
            report_diagnostics(context);
            cleanup_context(context);
            free(context);
            return 0;
        }

        store_message(context->error_message,
                      sizeof(context->error_message),
                      "unable to read testcase file");
        report_diagnostics(context);
        cleanup_context(context);
        free(context);
        return 2;
    }

    context->png_ptr = png_create_read_struct(
        PNG_LIBPNG_VER_STRING,
        context,
        png_error_callback,
        png_warning_callback);

    if (context->png_ptr == NULL) {
        if (context->error_message[0] == '\0') {
            store_message(context->error_message,
                          sizeof(context->error_message),
                          "png_create_read_struct failed");
        }

        report_diagnostics(context);
        cleanup_context(context);
        free(context);
        return 2;
    }

    /*
     * Explicitly request libpng's compatible jump buffer. Check for failure
     * before any operation that can invoke the fatal-error callback.
     */
    jmp_buf *jump_buffer =
        png_set_longjmp_fn(context->png_ptr, longjmp, sizeof(jmp_buf));

    if (jump_buffer == NULL) {
        context->harness_failure = 1;
        store_message(context->error_message,
                      sizeof(context->error_message),
                      "unable to establish libpng jump buffer");
        report_diagnostics(context);
        cleanup_context(context);
        free(context);
        return 2;
    }

    if (setjmp(*jump_buffer) != 0) {
        report_diagnostics(context);

        int result = context->harness_failure ? 2 : 0;
        cleanup_context(context);
        free(context);
        return result;
    }

    context->info_ptr = png_create_info_struct(context->png_ptr);
    if (context->info_ptr == NULL) {
        context->harness_failure = 1;
        store_message(context->error_message,
                      sizeof(context->error_message),
                      "png_create_info_struct failed");
        report_diagnostics(context);
        cleanup_context(context);
        free(context);
        return 2;
    }

    context->end_info_ptr = png_create_info_struct(context->png_ptr);
    if (context->end_info_ptr == NULL) {
        context->harness_failure = 1;
        store_message(context->error_message,
                      sizeof(context->error_message),
                      "png_create end-info structure failed");
        report_diagnostics(context);
        cleanup_context(context);
        free(context);
        return 2;
    }

    png_set_read_fn(context->png_ptr, context, png_memory_read);

    /* Apply the approved pilot resource limits before reading metadata. */
    png_set_user_limits(context->png_ptr,
                        MAX_IMAGE_WIDTH, MAX_IMAGE_HEIGHT);
    png_set_chunk_malloc_max(context->png_ptr,
                             (png_alloc_size_t)MAX_CHUNK_BYTES);
    png_set_chunk_cache_max(context->png_ptr, MAX_CACHED_CHUNKS);

    /*
     * Coverage-oriented policy: use data from chunks with bad CRCs so that
     * mutations can reach deeper parsing code. This is not strict CRC testing.
     */
    png_set_crc_action(context->png_ptr,
                       PNG_CRC_QUIET_USE,
                       PNG_CRC_QUIET_USE);

    png_read_info(context->png_ptr, context->info_ptr);

    png_uint_32 width = 0U;
    png_uint_32 height = 0U;
    int bit_depth = 0;
    int color_type = 0;
    int interlace_type = 0;
    int compression_type = 0;
    int filter_method = 0;

    if (png_get_IHDR(context->png_ptr, context->info_ptr,
                     &width, &height, &bit_depth, &color_type,
                     &interlace_type, &compression_type,
                     &filter_method) == 0U) {
        png_error(context->png_ptr, "PNG header information unavailable");
    }

    if (width == 0U || height == 0U ||
        width > MAX_IMAGE_WIDTH || height > MAX_IMAGE_HEIGHT) {
        png_error(context->png_ptr, "image dimensions exceed pilot limits");
    }

    /* Division avoids overflow in the width * height pixel-budget check. */
    if ((size_t)height > (size_t)MAX_TOTAL_PIXELS / (size_t)width) {
        png_error(context->png_ptr, "image exceeds total pixel budget");
    }

    int passes = png_set_interlace_handling(context->png_ptr);
    if (passes <= 0)
        png_error(context->png_ptr, "invalid interlace pass count");

    png_read_update_info(context->png_ptr, context->info_ptr);

    png_size_t row_bytes =
        png_get_rowbytes(context->png_ptr, context->info_ptr);

    if (row_bytes == 0U || row_bytes > (png_size_t)MAX_ROW_BYTES) {
        png_error(context->png_ptr, "decoded row exceeds 64 KiB limit");
    }

    /*
     * This is a parser/decoder coverage harness, not a pixel-output checker.
     * Passing NULL avoids retaining or combining pixel rows between Adam7
     * passes. Libpng still processes the sequential image data.
     */
    for (int pass = 0; pass < passes; ++pass) {
        for (png_uint_32 row = 0U; row < height; ++row) {
            png_read_row(context->png_ptr, NULL, NULL);
        }
    }

    /* A non-NULL end-info pointer exercises post-IDAT ancillary parsing. */
    png_read_end(context->png_ptr, context->end_info_ptr);

    report_diagnostics(context);
    cleanup_context(context);
    free(context);
    return 0;
}
