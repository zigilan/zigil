#ifndef ZIGIL_SCANNER_HH_
#define ZIGIL_SCANNER_HH_

#include "zigil/pattern.hh"
#include "zigil/analyzer/pe_analyzer.hh"
#include "zigil/detail/fixed_string.hh"
#include "zigil/detail/hash.hh"

#include <optional>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace zigil {
	enum class CaptureKind : uint8_t {
		kNone,
		kRegister,
		kImmediate,
		/* a resolved rip-relative or branch target, always stored as an RVA */
		kAddress,
		kMemory
	};
	struct Capture {
		CaptureKind kind = CaptureKind::kNone;
		ZydisRegister reg = ZYDIS_REGISTER_NONE;
		int64_t value = 0;
		/* encoded width of the value in bits, 0 when it does not apply */
		uint8_t width = 0;
		/*
		* Set on a pre-bound value seeded as a plain number: it then satisfies an
		* immediate as well as a resolved address, because the caller cannot know
		* which of the two the instruction will produce.
		*/
		bool numeric_any = false;

		// only filled for CaptureKind::kMemory
		ZydisRegister mem_segment = ZYDIS_REGISTER_NONE;
		ZydisRegister mem_base = ZYDIS_REGISTER_NONE;
		ZydisRegister mem_index = ZYDIS_REGISTER_NONE;
		uint8_t mem_scale = 0;
	};
	/*
	* One match, plus whatever the pattern captured. Addresses are RVAs; GetVA
	* adds the image base, which is the only place the image base enters.
	*/
	class MatchResult {
	public:
		uint64_t Rva() const { return rva_; }
		uint64_t Va() const { return image_base_ + rva_; }
		/* RVA of the instruction that follows the last one the pattern matched */
		uint64_t NextRva() const { return next_rva_; }
		size_t CaptureCount() const { return captures_.size(); }
		const Capture* CaptureAt(size_t index) const {
			return index < captures_.size() ? &captures_[index] : nullptr;
		}

		template<typename T>
		T Get(std::string_view name) const {
			return Cast<T>(FindCapture(detail::Fnv1a(name)));
		}
		template<typename T, detail::FixedString Name>
		T Get() const {
			constexpr uint64_t hash = detail::Fnv1a(Name.View());
			return Cast<T>(FindCapture(hash));
		}
		template<typename T>
		T GetVA(std::string_view name) const {
			return CastVA<T>(FindCapture(detail::Fnv1a(name)));
		}
		template<typename T, detail::FixedString Name>
		T GetVA() const {
			constexpr uint64_t hash = detail::Fnv1a(Name.View());
			return CastVA<T>(FindCapture(hash));
		}
		bool Has(std::string_view name) const {
			return FindCapture(detail::Fnv1a(name)) != nullptr;
		}

		void Print() const;

	private:
		friend class Scanner;

		const Capture* FindCapture(uint64_t hash) const {
			for (size_t i = 0; i < hashes_.size() && i < captures_.size(); i++) {
				if (hashes_[i] == hash) {
					return captures_[i].kind == CaptureKind::kNone ? nullptr : &captures_[i];
				}
			}
			return nullptr;
		}
		template<typename T>
		T Cast(const Capture* capture) const {
			if (!capture) {
				return T{};
			}
			if constexpr (std::is_same_v<std::remove_cv_t<T>, ZydisRegister>) {
				return capture->reg;
			}
			else if constexpr (std::is_enum_v<T>) {
				return (T)(std::underlying_type_t<T>)capture->value;
			}
			else {
				return (T)capture->value;
			}
		}
		template<typename T>
		T CastVA(const Capture* capture) const {
			if (!capture) {
				return T{};
			}
			return (T)(image_base_ + (uint64_t)capture->value);
		}

	private:
		uint64_t rva_ = 0;
		uint64_t next_rva_ = 0;
		uint64_t image_base_ = 0;
		std::vector<Capture> captures_;
		std::vector<uint64_t> hashes_;
	};
	/*
	* Matches patterns against the instruction index the analyzer produced. The
	* scan iterates that bitmap in ascending RVA and re-decodes on demand, so
	* "the next instruction" always means the next instruction the analyzer
	* decoded, in address order - it does not stop at ret, padding or function
	* boundaries.
	*/
	class Scanner {
	public:
		explicit Scanner(const analyzer::PEAnalyzer& analyzer);

		/* first match at or after start_rva */
		std::optional<MatchResult> Find(PatternView pattern, uint64_t start_rva = 0) const;
		/* every match; limit == 0 means no limit */
		std::vector<MatchResult> FindAll(PatternView pattern, size_t limit = 0) const;

		/*
		* Several patterns in a single pass. Result i holds the matches for
		* patterns[i], in the same order FindAll would have produced them.
		*
		* The walk over the instruction index is shared, so N separate FindAll
		* calls pay for it N times over while this pays once. What a second
		* pattern adds on top of that is decided by how common the mnemonic it
		* opens on is: every candidate opening on the same mnemonic shares one
		* full decode of each address they all reach, and one that opens on a
		* rare mnemonic barely enters the matcher at all.
		*
		* Pre-bound variables are shared, which is what they already are: bind
		* them under distinct names and each pattern picks up its own.
		*/
		std::vector<std::vector<MatchResult>> FindAll(std::span<const PatternView> patterns,
			size_t limit_each = 0) const;

		/*
		* Pre-bound variables. A variable seeded here is enforced instead of
		* captured when the pattern first reaches it, which is what turns a
		* pattern into an xref search:
		*
		*   scanner.SetAddress("target", global_rva);
		*   scanner.FindAll(R"(mov $reg:r64, [rip+$target:imm])"_sig.View());
		*
		* Because a resolved address depends on where the instruction sits, this
		* is the one case where matching is position dependent.
		*
		* A type suffix on a pre-bound variable acts as an assertion: seeding a
		* register into `$x:imm` (or the other way round) is reported and the scan
		* returns nothing rather than silently never matching.
		*/
		void Set(std::string_view name, ZydisRegister reg);
		/* an RVA, not a VA - subtract the image base first */
		void SetAddress(std::string_view name, uint64_t rva);
		void SetImmediate(std::string_view name, int64_t value, uint8_t width = 0);
		/* matches an immediate or a resolved address with this value */
		void Set(std::string_view name, uint64_t value);
		void Unset(std::string_view name);
		void UnsetAll() { prebound_.clear(); }
		size_t PreboundCount() const { return prebound_.size(); }

		/*
		* How many instructions an open ended gap (<?>, <N+>) may skip. Without a
		* bound a failed match would walk to the end of the section every time.
		*/
		void SetSkipLimit(uint32_t limit) { skip_limit_ = limit; }
		uint32_t SkipLimit() const { return skip_limit_; }

		/*
		* Worker threads a scan may use; 0 means one per hardware thread and 1
		* keeps the scan on the calling thread. The split is over ranges of
		* instruction starts and the results are merged in address order, so the
		* thread count changes nothing about what a scan returns.
		*
		* A limited scan (Find, or FindAll with a limit) stays single threaded:
		* it stops early, and a thread cannot know what the others have already
		* found without making the result depend on who got there first.
		*/
		void SetThreadCount(unsigned threads) { threads_ = threads; }
		unsigned ThreadCount() const { return threads_; }

	private:
		struct PreBound {
			uint64_t hash;
			Capture capture;
		};
		/*
		* One address decoded with its operands, so the candidates that open on
		* the same mnemonic can share it. Without this each of them re-runs a
		* full ZydisDecoderDecodeFull of the same address before it can reject on
		* an operand, and on a common opening mnemonic - a mov is a quarter of
		* the image - those repeated decodes are most of what a pass costs.
		*/
		struct DecodedInstruction {
			ZydisDecodedInstruction inst;
			ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
		};

		void SetCapture(std::string_view name, const Capture& capture);
		/* captures vector with every pre-bound variable of this pattern filled in */
		std::vector<Capture> SeedCaptures(PatternView pattern) const;
		const Capture* PreboundFor(PatternView pattern, uint8_t var_idx) const;
		/* reports type conflicts between the pre-bound values and the pattern */
		bool ValidatePrebound(PatternView pattern) const;

		/*
		* The candidates of one scan in the form the inner loop wants them:
		* immutable for the whole pass, and bucketed by the mnemonic each pattern
		* opens on. Shared by every worker thread, which is why nothing in here
		* is written once a scan has started.
		*/
		struct ScanSet {
			struct Candidate {
				PatternView pattern;
				std::vector<Capture> seed;
				/* which entry of Collect's `out` this candidate's matches go to */
				size_t out_index;
			};
			std::vector<Candidate> candidates;
			std::unordered_map<ZydisMnemonic, std::vector<size_t>> by_mnemonic;
			/* patterns opening with a gap, which match from any instruction start */
			std::vector<size_t> anywhere;
		};
		/* one worker's mutable state, carried across the ranges it covers */
		struct ScanState {
			std::vector<bool> done;
			size_t remaining = 0;
			std::vector<Capture> scratch;
		};

		/* one pass over the instruction index; limit == 0 collects everything */
		void Collect(std::span<const PatternView> patterns, uint64_t start_rva, size_t limit_each,
			std::span<std::vector<MatchResult>> out) const;
		/*
		* Every instruction start in [begin, end) matched against every candidate,
		* appending to `out` indexed by candidate rather than by pattern. A match
		* may run past `end` - the range partitions where a pattern may start, not
		* what it may read - so the ranges together produce exactly what one pass
		* over the whole image would have.
		*/
		void ScanRange(const ScanSet& set, uint64_t begin, uint64_t end, size_t limit_each,
			ScanState& state, std::span<std::vector<MatchResult>> out) const;
		bool Decode(uint64_t rva, ZydisDecodedInstruction& inst) const;
		bool DecodeFull(uint64_t rva, ZydisDecodedInstruction& inst,
			ZydisDecodedOperand* operands) const;
		/* first instruction start at or after rva + length, 0 when there is none */
		uint64_t NextStart(uint64_t rva, uint8_t length) const;

		/*
		* `scratch` is the caller's working buffer for the capture set, reused
		* across candidates. Copying the seed into a fresh vector per candidate
		* is a heap allocation for every instruction that clears the mnemonic
		* filter, and on a common opening mnemonic that is millions of them.
		*
		* `decoded` is the instruction at `rva` already decoded by the caller, or
		* null to decode it here. It only ever describes the pattern's first
		* instruction, so it is not forwarded past index 0.
		*/
		bool MatchAt(PatternView pattern, uint64_t rva, const std::vector<Capture>& seed,
			std::vector<Capture>& scratch, const DecodedInstruction* decoded,
			MatchResult& out) const;
		bool MatchFrom(PatternView pattern, size_t index, uint64_t rva,
			std::vector<Capture>& captures, uint64_t& next_rva,
			const DecodedInstruction* decoded) const;
		bool MatchInstructionAt(const MatchInstruction& pattern, uint64_t rva,
			std::vector<Capture>& captures, uint8_t& length,
			const DecodedInstruction* decoded) const;
		bool MatchOperand(const Operand& pattern, const ZydisDecodedInstruction& inst,
			const ZydisDecodedOperand& op, uint8_t imm_slot, uint64_t rva,
			std::vector<Capture>& captures) const;
		bool MatchMemory(const MemOperand& pattern, const ZydisDecodedInstruction& inst,
			const ZydisDecodedOperand& op, uint64_t rva, std::vector<Capture>& captures) const;
		Capture CaptureFromOperand(const ZydisDecodedInstruction& inst,
			const ZydisDecodedOperand& op, uint8_t imm_slot, uint64_t rva) const;
		bool BindOrCheck(uint8_t var_idx, const Capture& value, RegWidth width,
			std::vector<Capture>& captures) const;

	private:
		const analyzer::PEAnalyzer* analyzer_ = nullptr;
		const uint8_t* image_ = nullptr;
		size_t size_ = 0;
		const std::vector<bool>* starts_ = nullptr;
		ZydisDecoder decoder_{};
		uint32_t skip_limit_ = 256;
		unsigned threads_ = 0;
		std::vector<PreBound> prebound_;
	};
} // namespace zigil

#endif // ZIGIL_SCANNER_HH_
