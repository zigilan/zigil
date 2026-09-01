#ifndef ZIGIL_DETAIL_FIXED_STRING_HH_
#define ZIGIL_DETAIL_FIXED_STRING_HH_

#include <cstdint>
#include <string_view>

namespace zigil::detail {
	/*
	* A variable name kept by value, so a pattern can carry its own names without
	* owning a std::string. Only used when names are kept at all - see
	* ZIGIL_KEEP_VARIABLE_NAMES in parser.hh. Longer names still hash in full, so
	* matching is unaffected; only the display is truncated.
	*/
	struct VarName {
		static constexpr size_t kCapacity = 47;

		char data[kCapacity]{};
		uint8_t length = 0;

		constexpr VarName() = default;
		constexpr VarName(std::string_view name) {
			length = (uint8_t)(name.size() < kCapacity ? name.size() : kCapacity);
			for (uint8_t i = 0; i < length; i++) {
				data[i] = name[i];
			}
		}
		constexpr std::string_view View() const {
			return std::string_view(data, length);
		}
	};
	template<size_t N>
	struct FixedString {
		char data[N]{};

		constexpr FixedString(const char(&str)[N]) {
			for (size_t i = 0; i < N; i++) {
				data[i] = str[i];
			}
		}

		constexpr std::string_view View() const {
			return std::string_view(data, N - 1);
		}
	};
} // namespace zigil::detail

#endif // ZIGIL_DETAIL_FIXED_STRING_HH_