/*
* C API for zigil, for callers that are not C++: analyze an image, compile a
* pattern, find every match and read its captures.
*
* Every object is opaque and owned by the caller, who frees it with the
* matching *_free function. Functions that can fail take an optional error
* buffer (may be null) and return null on failure, with a NUL-terminated
* message in the buffer. Nothing here prints, except the analyzer's own
* diagnostics for an image it cannot use.
*
* Addresses are RVAs throughout; add zigil_image_base for a VA.
*/
#ifndef ZIGIL_ZIGIL_C_H_
#define ZIGIL_ZIGIL_C_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZIGIL_C_API_VERSION 1

typedef struct zigil_image zigil_image;
typedef struct zigil_pattern zigil_pattern;
typedef struct zigil_matches zigil_matches;

typedef enum zigil_capture_kind {
	ZIGIL_CAPTURE_NONE = 0,
	ZIGIL_CAPTURE_REGISTER = 1,
	ZIGIL_CAPTURE_IMMEDIATE = 2,
	/* a resolved rip-relative or branch target, as an RVA */
	ZIGIL_CAPTURE_ADDRESS = 3,
	ZIGIL_CAPTURE_MEMORY = 4
} zigil_capture_kind;

typedef struct zigil_capture {
	/* a zigil_capture_kind */
	uint32_t kind;
	/* encoded width of the value in bits, 0 when it does not apply */
	uint32_t width;
	/* immediate, address (RVA) or memory displacement */
	int64_t value;
	/* register name for ZIGIL_CAPTURE_REGISTER, e.g. "rcx"; static storage */
	const char* reg;
	/* ZIGIL_CAPTURE_MEMORY only; register names are "" when absent */
	const char* mem_segment;
	const char* mem_base;
	const char* mem_index;
	uint32_t mem_scale;
} zigil_capture;

/* a pre-bound variable: enforced instead of captured, see Scanner::Set */
typedef struct zigil_binding {
	const char* name;
	/* an immediate or an RVA; matches either */
	uint64_t value;
} zigil_binding;

int zigil_api_version(void);

/*
* Analyzes a 64-bit PE image. `loaded` != 0 means the bytes are already in
* virtual layout (a module read from a running process); 0 means a file as it
* is on disk. The bytes are copied, so the buffer may be freed afterwards.
*/
zigil_image* zigil_image_analyze(const uint8_t* data, size_t size, int loaded,
	char* error, size_t error_size);
uint64_t zigil_image_base(const zigil_image* image);
size_t zigil_image_size(const zigil_image* image);
/* number of instruction starts the analyzer found */
size_t zigil_image_instruction_count(const zigil_image* image);
void zigil_image_free(zigil_image* image);

/* `text` need not be NUL-terminated; one instruction per line */
zigil_pattern* zigil_pattern_compile(const char* text, size_t length,
	char* error, size_t error_size);
size_t zigil_pattern_variable_count(const zigil_pattern* pattern);
/* the variable's name without the '$', NUL-terminated; null when out of range */
const char* zigil_pattern_variable_name(const zigil_pattern* pattern, size_t index);
void zigil_pattern_free(zigil_pattern* pattern);

/*
* Every match of `pattern` in `image`, in address order. `limit` == 0 means no
* limit. `bindings` may be null when `binding_count` is 0. Returns null only on
* an error (out of memory, or a binding the pattern cannot accept); no match is
* an empty result.
*/
zigil_matches* zigil_find_all(const zigil_image* image, const zigil_pattern* pattern,
	size_t limit, const zigil_binding* bindings, size_t binding_count,
	char* error, size_t error_size);
size_t zigil_matches_count(const zigil_matches* matches);
/* RVA of the first instruction of match `index` */
uint64_t zigil_match_rva(const zigil_matches* matches, size_t index);
/* RVA just past the last instruction the pattern matched */
uint64_t zigil_match_end_rva(const zigil_matches* matches, size_t index);
/*
* Capture of variable `variable` (an index as for zigil_pattern_variable_name)
* in match `index`. Returns 0 and leaves `out` alone when either is out of range.
*/
int zigil_match_capture(const zigil_matches* matches, size_t index, size_t variable,
	zigil_capture* out);
void zigil_matches_free(zigil_matches* matches);

#ifdef __cplusplus
}
#endif

#endif /* ZIGIL_ZIGIL_C_H_ */
