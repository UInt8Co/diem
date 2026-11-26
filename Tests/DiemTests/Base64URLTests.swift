import Diem
import Testing

@Suite struct Base64URLTests {
  @Test func encodesUnpaddedURLSafeText() {
    #expect(Base64URL.encode([]) == "")
    #expect(Base64URL.encode([251, 255]) == "-_8")
    #expect(Base64URL.encode(Array("diem".utf8)) == "ZGllbQ")
    #expect(Base64URL.decode("ZGllbQ") == Array("diem".utf8))
    #expect(Base64URL.decode("-_8") == [251, 255])
  }

  @Test func decodesOnlyTheCanonicalSpelling() {
    // Padding, the standard alphabet, whitespace, an impossible length, unused bits.
    for text in ["ZGllbQ==", "+/8", " ZGllbQ", "ZGllb", "ZGllbR", "💥"] {
      #expect(Base64URL.decode(text) == nil)
    }
    #expect(Base64URL.decode("AAAA", maximumBytes: 3) == [0, 0, 0])
    #expect(Base64URL.decode("AAAAAA", maximumBytes: 3) == nil)
  }
}
