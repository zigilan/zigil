#ifndef ZIGIL_LEXER_HH_
#define ZIGIL_LEXER_HH_

#include <array>
#include <cstdio>
#include <format>
#include <string>
#include <string_view>
#include <vector>

namespace zigil {
	namespace detail {
		/*
		* Where runtime parse errors go. Null - the default - prints them; the C
		* API points it at a string for the duration of one parse to hand the
		* first message back to its caller instead.
		*/
		inline thread_local std::string* error_sink = nullptr;

		inline void ReportError(const std::string& message) {
			if (!error_sink) {
				printf("Error: %s\n", message.c_str());
			}
			else if (error_sink->empty()) {
				*error_sink = message;
			}
		}
	} // namespace detail

	enum class TokenType : uint8_t {
		kInvalid,
		kNumber,
		kIdentifier,
		kLessThan,
		kGreaterThan,
		kColon,
		kDollar,
		kQuestion,
		kBracketOpen,
		kBracketClose,
		kComma,
		kPlus,
		kMinus,
		kStar,
		kNewline,
		kEOF
	};
	struct Token {
		TokenType type;
		union Value {
			std::string_view str;
			uint64_t num;

			constexpr Value() : str() {}
			constexpr Value(std::string_view str) : str(str) {}
			constexpr Value(uint64_t num) : num(num) {}
		} value;

		size_t line;
		size_t column;

		constexpr Token() : Token(TokenType::kInvalid) {}
		constexpr Token(TokenType type) : type(type), value(), line(0), column(0) {}
		constexpr Token(TokenType type, std::string_view str) : type(type), value(str), line(0), column(0) {}
		constexpr Token(TokenType type, uint64_t num) : type(type), value(num), line(0), column(0) {}

		constexpr std::string ValueToString() const;
		void Print() const;
		/*
		* At runtime this prints the formatted message with line and column.
		*
		* During constant evaluation it does nothing on purpose. Throwing here used
		* to turn a bad pattern into a compile error, but MSVC reports neither the
		* thrown value nor the format arguments - it emits C3615 plus a call stack
		* and the message is lost either way. The parse instead returns an empty
		* pattern, which `Parser::Parse<Query>()` turns into a static_assert that
		* says to re-parse the same string at runtime for the real message.
		*/
		template <typename... Args>
		constexpr void PrintError(std::format_string<Args...> fmt, Args&&... args) const {
			if (!std::is_constant_evaluated()) {
				std::string msg = std::format(fmt, std::forward<Args>(args)...);
				detail::ReportError(std::format("{} at Line {}, Column {}", msg, line, column));
			}
		}
	};

	class Lexer {
		friend class LexerTests;

	public:
		static constexpr std::vector<Token> Tokenize(std::string_view query);

	private:
		static constexpr bool IsDigit(char c);
		static constexpr bool IsHexDigit(char c);
		// check if `c` is a digit before calling, produces garbage otherwise
		static constexpr uint8_t DigitValue(char c);
		// check if `c` is a digit before calling, produces garbage otherwise
		static constexpr uint8_t HexDigitValue(char c);
		static constexpr bool IsWhitespace(char c);
		static constexpr TokenType GetCharTokenType(char c);
		static constexpr bool ParseNumber(std::string_view& src, uint64_t& num);
		/*
		* token_start, when given, receives where the token actually begins.
		* NextToken skips whitespace and comments internally, so the caller cannot
		* work that position out on its own - measuring before the call points at
		* the first skipped character instead of at the token.
		*/
		static constexpr Token NextToken(std::string_view& src,
			const char** token_start = nullptr);

	private:
		static constexpr std::array kWhitespace = {
			' ', '\t', '\r'
		};
	};

	constexpr std::string_view TokenTypeToString(TokenType t) {
		switch (t) {
		case TokenType::kInvalid: return "Invalid";
		case TokenType::kNumber: return "Number";
		case TokenType::kIdentifier: return "Identifier";
		case TokenType::kLessThan: return "LessThan";
		case TokenType::kGreaterThan: return "GreaterThan";
		case TokenType::kColon: return "Colon";
		case TokenType::kDollar: return "Dollar";
		case TokenType::kQuestion: return "Question";
		case TokenType::kBracketOpen: return "BracketOpen";
		case TokenType::kBracketClose: return "BracketClose";
		case TokenType::kComma: return "Comma";
		case TokenType::kPlus: return "Plus";
		case TokenType::kMinus: return "Minus";
		case TokenType::kStar: return "Star";
		case TokenType::kNewline: return "Newline";
		case TokenType::kEOF: return "EOF";
		default: return "?";
		}
	}

	constexpr std::string Token::ValueToString() const {
		if (type == TokenType::kNumber) {
			return std::format("{:#x}", value.num);
		}
		if (type == TokenType::kNewline || value.str.empty()) {
			return "";
		}
		return std::string(value.str);
	}
	inline void Token::Print() const {
		printf(
			"%-15s %s\n",
			TokenTypeToString(type).data(),
			ValueToString().c_str()
		);
	}

	constexpr std::vector<Token> Lexer::Tokenize(std::string_view query) {
		std::vector<Token> tokens;
		std::string_view src = query;
		const char* srcstart = src.data();
		Token token;
		size_t line = 1;
		size_t line_start = 0;
		do {
			const char* token_start = src.data();
			token = NextToken(src, &token_start);
			token.line = line;
			token.column = (size_t)(token_start - srcstart) - line_start;
			if (token.type == TokenType::kInvalid) {
				token.PrintError("Invalid Token");
				return {};
			}
			if (token.type == TokenType::kNewline) {
				line++;
				line_start = src.data() - srcstart;
			}
			tokens.push_back(token);
		} while (token.type != TokenType::kEOF);

		return tokens;
	}

	constexpr bool Lexer::IsDigit(char c) {
		return c >= '0' && c <= '9';
	}
	constexpr bool Lexer::IsHexDigit(char c) {
		const char lower = c | 0x20;
		return IsDigit(c) ||
			(lower >= 'a' && lower <= 'f');
	}
	constexpr uint8_t Lexer::DigitValue(char c) {
		return c - '0';
	}
	constexpr uint8_t Lexer::HexDigitValue(char c) {
		if (IsDigit(c)) return DigitValue(c);
		return (c | 0x20) - // to lowercase
			'a' + 10;
	}
	constexpr bool Lexer::IsWhitespace(char c) {
		for (char d : kWhitespace) {
			if (c == d) {
				return true;
			}
		}
		return false;
	}
	constexpr TokenType Lexer::GetCharTokenType(char c) {
		switch (c) {
		case '<': return TokenType::kLessThan;
		case '>': return TokenType::kGreaterThan;
		case ':': return TokenType::kColon;
		case '$': return TokenType::kDollar;
		case '?': return TokenType::kQuestion;
		case '[': return TokenType::kBracketOpen;
		case ']': return TokenType::kBracketClose;
		case ',': return TokenType::kComma;
		case '+': return TokenType::kPlus;
		case '-': return TokenType::kMinus;
		case '*': return TokenType::kStar;
		case '\n': return TokenType::kNewline;
		default: return TokenType::kInvalid;
		}
	}
	constexpr bool Lexer::ParseNumber(std::string_view& src, uint64_t& num) {
		num = 0;
		if (src.front() == '0' && src.size() > 1) {
			char next = src[1];
			if (!IsDigit(next) &&
				!IsWhitespace(next) &&
				GetCharTokenType(next) == TokenType::kInvalid) {
				if (src.size() == 2) {
					return false;
				}
				switch (next) {
				case 'x':
				case 'X':
					src.remove_prefix(2);
					if (!IsHexDigit(src.front())) {
						return false;
					}
					while (!src.empty() &&
						!IsWhitespace(src.front()) &&
						GetCharTokenType(src.front()) == TokenType::kInvalid) {
						if (!IsHexDigit(src.front())) {
							return false;
						}
						const uint8_t digit = HexDigitValue(src.front());
						if (num > (UINT64_MAX - digit) / 16) {
							return false;
						}
						num = num * 16 + digit;
						src.remove_prefix(1);
					}
					break;
				case 'b':
				case 'B':
					src.remove_prefix(2);
					if (src.front() != '0' && src.front() != '1') {
						return false;
					}
					while (!src.empty() &&
						!IsWhitespace(src.front()) &&
						GetCharTokenType(src.front()) == TokenType::kInvalid) {
						if (src.front() != '0' && src.front() != '1') {
							return false;
						}
						const uint8_t digit = src.front() == '1';
						if (num > (UINT64_MAX - digit) / 2) {
							return false;
						}
						num = num * 2 + digit;
						src.remove_prefix(1);
					}
					break;
				default: return false;
				}
				return true;
			}
		}
		while (!src.empty() &&
			!IsWhitespace(src.front()) &&
			GetCharTokenType(src.front()) == TokenType::kInvalid) {
			if (!IsDigit(src.front())) {
				return false;
			}
			const uint8_t digit = DigitValue(src.front());
			if (num > (UINT64_MAX - digit) / 10) {
				return false;
			}
			num = num * 10 + digit;
			src.remove_prefix(1);
		}
		return true;
	}
	constexpr Token Lexer::NextToken(std::string_view& src, const char** token_start) {
		while (!src.empty()) {
			if (IsWhitespace(src.front())) {
				src.remove_prefix(1);
			}
			else if (src.front() == ';') {
				while (!src.empty() && src.front() != '\n') {
					src.remove_prefix(1);
				}
			}
			else {
				break;
			}
		}
		// everything skipped above is behind us, so this is where the token starts
		if (token_start) {
			*token_start = src.data();
		}
		if (src.empty()) {
			return Token(TokenType::kEOF);
		}

		const char* start = src.data();
		TokenType type = GetCharTokenType(src.front());
		if (type != TokenType::kInvalid) {
			src.remove_prefix(1);
			return Token(type, std::string_view(start, 1));
		}
		// check number
		if (IsDigit(src.front())) {
			uint64_t num;
			if (ParseNumber(src, num)) {
				return Token(TokenType::kNumber, num);
			}
			return Token(TokenType::kInvalid);
		}

		// none of the above matched so this must be an identifier
		while (!src.empty() &&
			!IsWhitespace(src.front()) &&
			GetCharTokenType(src.front()) == TokenType::kInvalid) {
			src.remove_prefix(1);
		}
		return Token(TokenType::kIdentifier, std::string_view(start, src.data()));
	}
} // namespace zigil

#endif // ZIGIL_LEXER_HH_