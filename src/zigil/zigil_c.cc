#include "zigil/zigil_c.h"

#include "zigil/analyzer/pe_analyzer.hh"
#include "zigil/parser.hh"
#include "zigil/scanner.hh"
#include "zigil/tables.hh"

#include <cstring>
#include <memory>
#include <string>
#include <vector>

struct zigil_image {
	/* the analyzer points into this when the image was loaded, so it lives here */
	std::vector<uint8_t> bytes;
	zigil::analyzer::PEAnalyzer analyzer;
	size_t instructions = 0;
};

struct zigil_pattern {
	zigil::Pattern pattern;
	/* NUL-terminated copies of the variable names, for the C side */
	std::vector<std::string> names;
};

struct zigil_matches {
	std::vector<zigil::MatchResult> results;
};

namespace {
	void SetError(char* error, size_t error_size, const std::string& message) {
		if (!error || error_size == 0) {
			return;
		}
		const size_t n = message.size() < error_size - 1 ? message.size() : error_size - 1;
		std::memcpy(error, message.data(), n);
		error[n] = '\0';
	}

	/* collects the first error reported while it is alive, instead of printing it */
	class ErrorScope {
	public:
		ErrorScope() : previous_(zigil::detail::error_sink) { zigil::detail::error_sink = &message_; }
		~ErrorScope() { zigil::detail::error_sink = previous_; }
		ErrorScope(const ErrorScope&) = delete;
		ErrorScope& operator=(const ErrorScope&) = delete;

		const std::string& Message() const { return message_; }

	private:
		std::string message_;
		std::string* previous_;
	};

	const char* RegisterName(ZydisRegister reg) {
		if (reg == ZYDIS_REGISTER_NONE) {
			return "";
		}
		/* the table's views point at string literals, so they are NUL-terminated */
		return zigil::tables::RegisterToString(reg).data();
	}
} // namespace

extern "C" {

int zigil_api_version(void) {
	return ZIGIL_C_API_VERSION;
}

zigil_image* zigil_image_analyze(const uint8_t* data, size_t size, int loaded,
	char* error, size_t error_size) {
	try {
		if (!data || size == 0) {
			SetError(error, error_size, "empty image");
			return nullptr;
		}
		auto image = std::make_unique<zigil_image>();
		image->bytes.assign(data, data + size);
		zigil::analyzer::AnalysisOptions options;
		options.progress = false;
		if (!image->analyzer.Analyze(image->bytes.data(), image->bytes.size(), loaded != 0, options)) {
			SetError(error, error_size, "not a 64-bit PE image zigil can analyze");
			return nullptr;
		}
		const auto& starts = image->analyzer.InstructionStarts();
		for (bool start : starts) {
			image->instructions += start;
		}
		return image.release();
	}
	catch (const std::exception& e) {
		SetError(error, error_size, e.what());
		return nullptr;
	}
}

uint64_t zigil_image_base(const zigil_image* image) {
	return image ? image->analyzer.ImageBase() : 0;
}

size_t zigil_image_size(const zigil_image* image) {
	return image ? image->analyzer.ImageSize() : 0;
}

size_t zigil_image_instruction_count(const zigil_image* image) {
	return image ? image->instructions : 0;
}

void zigil_image_free(zigil_image* image) {
	delete image;
}

zigil_pattern* zigil_pattern_compile(const char* text, size_t length,
	char* error, size_t error_size) {
	try {
		ErrorScope scope;
		auto pattern = std::make_unique<zigil_pattern>();
		pattern->pattern = zigil::Parser::Parse(std::string_view(text ? text : "", text ? length : 0));
		if (!scope.Message().empty()) {
			SetError(error, error_size, scope.Message());
			return nullptr;
		}
		if (pattern->pattern.instructions.empty()) {
			SetError(error, error_size, "empty pattern");
			return nullptr;
		}
		for (const auto& name : pattern->pattern.variable_names) {
			pattern->names.emplace_back(name.View());
		}
		return pattern.release();
	}
	catch (const std::exception& e) {
		SetError(error, error_size, e.what());
		return nullptr;
	}
}

size_t zigil_pattern_variable_count(const zigil_pattern* pattern) {
	return pattern ? pattern->pattern.variable_count : 0;
}

const char* zigil_pattern_variable_name(const zigil_pattern* pattern, size_t index) {
	if (!pattern || index >= pattern->names.size()) {
		return nullptr;
	}
	return pattern->names[index].c_str();
}

void zigil_pattern_free(zigil_pattern* pattern) {
	delete pattern;
}

zigil_matches* zigil_find_all(const zigil_image* image, const zigil_pattern* pattern,
	size_t limit, const zigil_binding* bindings, size_t binding_count,
	char* error, size_t error_size) {
	try {
		if (!image || !pattern) {
			SetError(error, error_size, "no image or pattern");
			return nullptr;
		}
		ErrorScope scope;
		zigil::Scanner scanner(image->analyzer);
		for (size_t i = 0; i < binding_count; i++) {
			if (bindings[i].name) {
				scanner.Set(bindings[i].name, bindings[i].value);
			}
		}
		auto matches = std::make_unique<zigil_matches>();
		matches->results = scanner.FindAll(pattern->pattern.View(), limit);
		if (!scope.Message().empty()) {
			SetError(error, error_size, scope.Message());
			return nullptr;
		}
		return matches.release();
	}
	catch (const std::exception& e) {
		SetError(error, error_size, e.what());
		return nullptr;
	}
}

size_t zigil_matches_count(const zigil_matches* matches) {
	return matches ? matches->results.size() : 0;
}

uint64_t zigil_match_rva(const zigil_matches* matches, size_t index) {
	if (!matches || index >= matches->results.size()) {
		return 0;
	}
	return matches->results[index].Rva();
}

uint64_t zigil_match_end_rva(const zigil_matches* matches, size_t index) {
	if (!matches || index >= matches->results.size()) {
		return 0;
	}
	return matches->results[index].NextRva();
}

int zigil_match_capture(const zigil_matches* matches, size_t index, size_t variable,
	zigil_capture* out) {
	if (!matches || !out || index >= matches->results.size()) {
		return 0;
	}
	const zigil::Capture* capture = matches->results[index].CaptureAt(variable);
	if (!capture) {
		return 0;
	}
	zigil_capture c{};
	c.kind = (uint32_t)capture->kind;
	c.width = capture->width;
	c.value = capture->value;
	c.reg = RegisterName(capture->reg);
	c.mem_segment = RegisterName(capture->mem_segment);
	c.mem_base = RegisterName(capture->mem_base);
	c.mem_index = RegisterName(capture->mem_index);
	c.mem_scale = capture->mem_scale;
	*out = c;
	return 1;
}

void zigil_matches_free(zigil_matches* matches) {
	delete matches;
}

} // extern "C"
