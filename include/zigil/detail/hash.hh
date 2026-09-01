#ifndef ZIGIL_DETAIL_HASH_HH_
#define ZIGIL_DETAIL_HASH_HH_

#include <cstdint>
#include <string_view>

namespace zigil::detail {
	constexpr uint64_t Fnv1a(std::string_view s) {
		uint64_t h = 0xcbf29ce484222325ull;
		for (char c : s) {
			h ^= (uint8_t)c; h *= 0x00000100000001b3ull;
		}
		return h;
	}
} // namespace zigil::detail

#endif // ZIGIL_DETAIL_HASH_HH_