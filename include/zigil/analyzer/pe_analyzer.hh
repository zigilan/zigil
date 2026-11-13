#ifndef ZIGIL_ANALYZER_PE_ANALYZER_HH_
#define ZIGIL_ANALYZER_PE_ANALYZER_HH_

#include <Zydis/Zydis.h>

#include <cstdint>
#include <string>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
// lower case, so it also resolves on a case-sensitive file system (MinGW)
#include <windows.h>

namespace zigil::analyzer {
	struct Section {
		std::string name;
		uint32_t va = 0;
		uint32_t vsize = 0;
		uint32_t characteristics = 0;
		bool executable = false;

		constexpr uint64_t End() const { return (uint64_t)va + vsize; }
		constexpr bool Contains(uint64_t rva) const { return rva >= va && rva < End(); }
	};
	struct AnalysisOptions {
		bool scan_exports = true;
		bool scan_tls = true;
		bool scan_unwind_handlers = true;
		bool scan_pointers = true;
		bool scan_jump_tables = true;
		bool scan_prologues = true;
		bool sweep_gaps = true;
		/*
		* Skip write+execute sections in the aggressive stages (prologue scan and
		* gap sweep). A section that is writable and executable holds packed or
		* self-modifying code at rest, so decoding it statically as x86 produces
		* noise, not coverage. Recursive descent still enters such a section when
		* a real branch points there.
		*/
		bool skip_writable_code = true;
		/*
		* Treat only these sections as code, by name. Empty -- the default --
		* means every section the PE marks executable, which is what a general
		* tool wants.
		*
		* The list is for a target whose executable range is mostly somebody
		* else's. Rainbow Six ships 291 MB of .text next to 109 MB of .UBX1
		* anti-tamper, and .UBX1 alone indexed 42.2 M instructions: 39% of the
		* work, in code no pattern will ever anchor on. `Section::executable`
		* is the single gate that recursive descent, every seeding stage, the
		* gap sweep and the scanner's own walk all read, so clearing it for the
		* rest removes them from all of it at once.
		*
		* Be deliberate about it. A pattern whose code lives in a section left
		* out does not match less well, it does not match at all, and nothing
		* says so -- which is why PrintReport and the section list still show
		* what was excluded.
		*/
		std::vector<std::string> code_sections;
		/* per-stage progress on stdout; errors are printed either way */
		bool progress = true;
	};
	struct AnalysisStats {
		size_t work_items = 0;
		size_t instructions = 0;
		size_t decode_failures = 0;

		size_t seeds_entry = 0;
		size_t seeds_pdata = 0;
		size_t seeds_exports = 0;
		size_t seeds_tls = 0;
		size_t seeds_handlers = 0;
		size_t seeds_pointers = 0;
		size_t seeds_jump_tables = 0;
		size_t seeds_prologues = 0;

		size_t jump_tables = 0;
		size_t data_bytes = 0;
		size_t sweep_instructions = 0;
	};
	/*
	* Turns a PE image into a flat, RVA-addressed byte buffer plus a bitmap of
	* every offset at which a decoded instruction starts. The matcher consumes
	* both through the accessors below.
	*
	* After Analyze() the single invariant that matters is: buffer offset == RVA
	* everywhere. A VA is always ImageBase() + RVA.
	*/
	class PEAnalyzer {
	public:
		PEAnalyzer() = default;
		// data_ may point into owned_, so neither copying nor moving is safe
		PEAnalyzer(const PEAnalyzer&) = delete;
		PEAnalyzer& operator=(const PEAnalyzer&) = delete;

		/**
		* `loaded` means the buffer is already in virtual layout (offset == RVA),
		* which is the case for a live process image. A file-aligned image is
		* flattened into an owned buffer first.
		*/
		bool Analyze(const uint8_t* data, size_t size, bool loaded = true,
			const AnalysisOptions& options = {});

		void PrintReport() const;

		bool IsAnalyzed() const { return data_ != nullptr; }
		const uint8_t* Image() const { return data_; }
		size_t ImageSize() const { return size_; }
		uint64_t ImageBase() const { return image_base_; }
		/* one bit per RVA, set at the first byte of every decoded instruction */
		const std::vector<bool>& InstructionStarts() const { return starts_; }
		const std::vector<Section>& Sections() const { return sections_; }
		const Section* SectionOf(uint64_t rva) const;
		const AnalysisStats& Stats() const { return stats_; }
		const ZydisDecoder& Decoder() const { return decoder_; }

	private:
		struct WorkItem {
			uint64_t begin;
			uint64_t end;
		};
		/*
		* Offsets of the last few instructions of the run currently being decoded.
		* Jump table extraction needs to look back at the dispatch sequence, and
		* re-decoding a handful of offsets is cheaper than carrying decoded
		* operands for every instruction.
		*/
		struct History {
			static constexpr size_t kSize = 16;

			uint64_t entries[kSize]{};
			size_t count = 0;

			void Clear() { count = 0; }
			void Push(uint64_t offset) { entries[count % kSize] = offset; ++count; }
			size_t Depth() const { return count < kSize ? count : kSize; }
			// 0 is the most recent instruction
			uint64_t Get(size_t back) const { return entries[(count - 1 - back) % kSize]; }
		};

		static bool ValidateHeaders(const uint8_t* data, size_t size, PIMAGE_NT_HEADERS64& nt);
		static std::vector<uint8_t> FlattenImage(const uint8_t* data, size_t size);

		bool BuildSectionMap();
		bool Enqueue(uint64_t rva, uint64_t end = 0);
		void MarkInstruction(uint64_t offset, uint8_t length);
		void MarkData(uint64_t rva, uint64_t length);
		/* returns true when the linear run ends here (ret / unconditional branch) */
		bool HandleInstruction(uint64_t offset, const ZydisDecodedInstruction& inst,
			const History& history);
		size_t Walk(const char* stage);

		void SeedEntryPoint();
		void SeedRuntimeFunctions();
		void SeedExports();
		void SeedTlsCallbacks();
		/* language-specific handler out of a function's UNWIND_INFO */
		void SeedUnwindHandler(uint32_t unwind_rva);
		void SeedPointerScan();
		void SeedPrologues();
		void SweepGaps();

		/* the dispatch site itself is never needed: the table is reached through
		 * the history, and every address in it is absolute or image base relative */
		void TryJumpTable(const ZydisDecodedInstruction& inst,
			const ZydisDecodedOperand* operands, const History& history);

		size_t CountCovered(const Section& section) const;

	private:
		std::vector<uint8_t> owned_;
		const uint8_t* data_ = nullptr;
		size_t size_ = 0;
		PIMAGE_NT_HEADERS64 nt_ = nullptr;
		uint64_t image_base_ = 0;

		AnalysisOptions opts_{};

		std::vector<Section> sections_;
		/* rva >> 12 -> index into sections_, 0xFFFF for a page in no section */
		std::vector<uint16_t> page_section_;

		std::vector<WorkItem> work_list_;
		/* instruction starts; this is the instruction index the matcher walks */
		std::vector<bool> starts_;
		/* every byte of every decoded instruction, so coverage counts each byte once */
		std::vector<bool> covered_;
		std::vector<bool> queued_;
		/* bytes known to be data (jump tables), excluded from the aggressive stages */
		std::vector<bool> is_data_;

		ZydisDecoder decoder_{};
		ZydisDecoderContext ctx_{};
		AnalysisStats stats_{};
		size_t covered_bytes_ = 0;
		double analysis_ms_ = 0.0;
	};
} // namespace zigil::analyzer

#endif // ZIGIL_ANALYZER_PE_ANALYZER_HH_
