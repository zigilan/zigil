#ifndef ZIGIL_ZIGIL_HH_
#define ZIGIL_ZIGIL_HH_

#include "zigil/parser.hh"

namespace zigil {
	inline namespace literals {
		template<detail::FixedString Query>
		consteval auto operator""_sig() {
			return Parser::Parse<Query>();
		}
	}
}

#endif // ZIGIL_ZIGIL_HH_