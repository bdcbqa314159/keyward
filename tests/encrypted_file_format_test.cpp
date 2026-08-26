// The encrypted-file format codec — pure parse/serialize + base64. No crypto, no
// I/O: entry values are opaque bytes here.
#include "keyward/encrypted_file_format.hpp"

#include <gtest/gtest.h>

#include <string>

using keyward::EncryptedFile;
using keyward::format_encrypted_file;
using keyward::is_encrypted_file;
using keyward::parse_encrypted_file;

namespace {
EncryptedFile sample() {
  EncryptedFile f;
  // Adjacent-literal breaks stop \x escapes eating the next (hex) char.
  f.salt = std::string(
      "\x00\x01\x02"
      "salt-with-nul",
      16);
  f.entries = {{"jira", std::string("nonce\x00mac\xff"
                                    "cipher",
                                    16)},
               {"fred", "opaque-bytes"}};
  return f;
}
}  // namespace

TEST(EncryptedFileFormat, RoundTrips) {
  EncryptedFile in = sample();
  auto out = parse_encrypted_file(format_encrypted_file(in));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->salt, in.salt);
  EXPECT_EQ(out->entries, in.entries);
}

TEST(EncryptedFileFormat, BinarySafeValuesViaBase64) {
  EncryptedFile in;
  in.salt = "s";
  in.entries = {{"k", std::string("\x00\n=\r\xff", 5)}};  // NUL, newline, '=', CR, high byte
  auto out = parse_encrypted_file(format_encrypted_file(in));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->entries, in.entries);
}

TEST(EncryptedFileFormat, EmptyEntriesRoundTrip) {
  EncryptedFile in;
  in.salt = "0123456789abcdef";
  auto out = parse_encrypted_file(format_encrypted_file(in));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->salt, in.salt);
  EXPECT_TRUE(out->entries.empty());
}

TEST(EncryptedFileFormat, PreservesEntryOrder) {
  EncryptedFile in;
  in.salt = "s";
  in.entries = {{"z", "1"}, {"a", "2"}, {"m", "3"}};
  auto out = parse_encrypted_file(format_encrypted_file(in));
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->entries, in.entries);  // order, not sorted
}

TEST(EncryptedFileFormat, DetectsMagic) {
  EXPECT_TRUE(is_encrypted_file("keyward-file-v2\nsalt=AA==\n"));
  EXPECT_FALSE(is_encrypted_file("jira=plaintext-secret\n"));  // legacy plaintext
  EXPECT_FALSE(is_encrypted_file(""));                         // empty / new file
  EXPECT_FALSE(is_encrypted_file("keyward-file-v3\n"));        // a version we don't know
}

TEST(EncryptedFileFormat, RejectsLegacyPlaintext) {
  // No magic -> not a v1 file -> parse fails (caller treats as legacy, fails closed).
  EXPECT_FALSE(parse_encrypted_file("jira=plaintext\n").has_value());
}

TEST(EncryptedFileFormat, RejectsMissingSaltHeader) {
  EXPECT_FALSE(parse_encrypted_file("keyward-file-v2\njira=AAAA\n").has_value());
}

TEST(EncryptedFileFormat, RejectsBadBase64) {
  // '!' isn't in the alphabet; a truncated/garbled entry must not parse partially.
  EXPECT_FALSE(parse_encrypted_file("keyward-file-v2\nsalt=AAAA\njira=not!base64\n").has_value());
  EXPECT_FALSE(parse_encrypted_file("keyward-file-v2\nsalt=@@@@\n").has_value());
}

TEST(EncryptedFileFormat, RejectsLineWithoutEquals) {
  EXPECT_FALSE(parse_encrypted_file("keyward-file-v2\nsalt=AAAA\ngarbage-no-equals\n").has_value());
}

TEST(EncryptedFileFormat, ToleratesTrailingBlankLines) {
  auto out = parse_encrypted_file("keyward-file-v2\nsalt=AAAA\njira=AAAA\n\n");
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->entries.size(), 1u);
}
