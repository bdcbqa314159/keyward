// Are libsodium's memory protections actually COMPILED IN?
//
// This is a regression test for a silent build-configuration failure, not for
// our own logic. The CMake wrapper that fetches libsodium performs no feature
// detection, so libsodium quietly compiled its FALLBACK allocator: sodium_malloc
// behaved as plain malloc. Zeroing still worked, which is what made it so easy to
// miss — Secret's header advertised "guard-paged, mlock'd" and nothing
// contradicted it. Measured at the time: pointer at page offset 0x10, a read one
// byte past the allocation succeeded, and no `lo`/`dd` VmFlags, meaning secrets
// could reach both swap and core dumps.
//
// keyward's CMakeLists now detects the primitives and passes them through. If a
// wrapper update, a toolchain change, or an edit to that block ever drops one,
// the build stays green and the protections silently vanish. Hence this test.
#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <string>

#include "keyward/secure_memory.hpp"

#if defined(__linux__)

#include <fstream>

namespace {

// The VmFlags line of the mapping containing `p`, or "" if it cannot be found.
// Parsing note: an smaps header line contains a device field like "00:00", so
// filtering on ':' would drop every header — the discriminator is that detail
// lines end in " kB".
std::string vmFlagsFor(const void* p) {
  const auto addr = reinterpret_cast<std::uintptr_t>(p);
  std::ifstream smaps("/proc/self/smaps");
  std::string line;
  bool inside = false;
  while (std::getline(smaps, line)) {
    unsigned long lo = 0, hi = 0;
    if (std::sscanf(line.c_str(), "%lx-%lx", &lo, &hi) == 2 &&
        line.find("kB") == std::string::npos) {
      inside = (addr >= lo && addr < hi);
    } else if (inside && line.rfind("VmFlags:", 0) == 0) {
      return line;
    }
  }
  return {};
}

bool hasFlag(const std::string& vmflags, const char* flag) {
  return vmflags.find(std::string(" ") + flag) != std::string::npos;
}

}  // namespace

// True when built with AddressSanitizer, which replaces the allocator and
// interferes with mlock specifically — the `dd` and guard-page checks below still
// hold under ASan, only this one does not.
#if defined(__SANITIZE_ADDRESS__)
#define KEYWARD_UNDER_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define KEYWARD_UNDER_ASAN 1
#endif
#endif

// mlock: the pages must never be written to swap, where they would outlive the
// process on disk.
TEST(SecureMemoryProtection, SecretPagesAreLockedAgainstSwap) {
#if defined(KEYWARD_UNDER_ASAN)
  GTEST_SKIP() << "ASan interferes with mlock — the `lo` flag does not appear even when "
                  "libsodium requests it. The un-sanitized build asserts this, and the "
                  "other two protections are still checked here.";
#endif
  void* p = keyward::secure_alloc(64);
  ASSERT_NE(p, nullptr);
  const std::string flags = vmFlagsFor(p);
  ASSERT_FALSE(flags.empty()) << "could not locate the mapping in /proc/self/smaps";
  EXPECT_TRUE(hasFlag(flags, "lo"))
      << "secure_alloc pages are NOT mlocked — libsodium fell back to plain malloc. "
      << "Check the feature detection in CMakeLists.txt. VmFlags: " << flags;
  keyward::secure_free(p);
}

// MADV_DONTDUMP: a core dump must not contain the secret. This is the protection
// DESIGN.md calls out as the weakest link.
TEST(SecureMemoryProtection, SecretPagesAreExcludedFromCoreDumps) {
  void* p = keyward::secure_alloc(64);
  ASSERT_NE(p, nullptr);
  const std::string flags = vmFlagsFor(p);
  ASSERT_FALSE(flags.empty()) << "could not locate the mapping in /proc/self/smaps";
  EXPECT_TRUE(hasFlag(flags, "dd"))
      << "secure_alloc pages are NOT marked MADV_DONTDUMP — they would land in a core "
      << "dump. Check the feature detection in CMakeLists.txt. VmFlags: " << flags;
  keyward::secure_free(p);
}

// Guard pages, checked by layout rather than by faulting: libsodium places the
// allocation flush against the trailing guard page, so the user pointer ends at a
// page boundary. Plain malloc puts it at a small header offset instead (0x10 was
// what the broken build produced). Asserting the layout avoids needing a SIGSEGV
// handler in the test process.
TEST(SecureMemoryProtection, AllocationIsFlushAgainstATrailingGuardPage) {
  constexpr std::size_t kSize = 64;
  void* p = keyward::secure_alloc(kSize);
  ASSERT_NE(p, nullptr);
  const auto offset = reinterpret_cast<std::uintptr_t>(p) & 0xFFFu;
  EXPECT_EQ(offset + kSize, 0x1000u)
      << "allocation is not flush against a page boundary (offset 0x" << std::hex << offset
      << ") — no trailing guard page, i.e. the fallback allocator is in use";
  keyward::secure_free(p);
}

#else  // not Linux

TEST(SecureMemoryProtection, SkippedOffLinux) {
  GTEST_SKIP() << "VmFlags-based checks are Linux-specific; the CMake feature detection "
                  "applies to any platform with sys/mman.h";
}

#endif
