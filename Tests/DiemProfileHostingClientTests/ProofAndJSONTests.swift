import Diem
import Foundation
import Testing
@testable import DiemProfileHostingClient

@Suite struct ProofAndJSONTests {
  let domain = try! DomainName("id.example")

  @Test func independentGoldenVector() async throws {
    // Python hashlib.sha256(prefix + n.to_bytes(8, 'big')), searching n from zero.
    let identity = try Digest(bytes: Array(1...32))
    let puzzle = try ProofOfWorkPuzzle(domain: domain, label: "alice",
      identityID: identity, requiredBits: 12)
    let nonce: [UInt8] = [0, 0, 0, 0, 0, 0, 0x22, 0x37]  // 8759
    #expect(Digest(hashing: puzzle.input + nonce).description
      == "000803d019da4a4a2495cbf46995aeb2eb343a59e0a16b40a78364faa345499a")
    #expect(puzzle.isSolved(by: nonce))
    #expect(try await PortableProofOfWorkSolver().solve(puzzle) == nonce)
    #expect(puzzle.expectedAttempts == 4096)
    #expect(!puzzle.isSolved(by: []))
    #expect(!puzzle.isSolved(by: Array(repeating: 0, count: 65)))
    let header = try hostingProofHeader(["bob": [251, 255], "alice": nonce])
    #expect(header == "alice=AAAAAAAAIjc, bob=-_8")
    for entry in header.components(separatedBy: ", ") {
      let pair = entry.components(separatedBy: "=")
      let value = pair[1].replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
      let decoded = try #require(Data(base64Encoded: value
        + String(repeating: "=", count: (4 - value.count % 4) % 4)))
      #expect(Array(decoded) == (pair[0] == "alice" ? nonce : [251, 255]))
    }
    #expect(throws: ProfileHostingError.invalidProof("alice")) {
      try hostingProofHeader(["alice": []])
    }
  }

  @Test func cancellationAndBounds() async throws {
    let puzzle = try ProofOfWorkPuzzle(domain: domain, label: "alice",
      identityID: Digest(hashing: []), requiredBits: 64)
    #expect(puzzle.expectedAttempts == 18_446_744_073_709_551_616.0)
    let task = Task { try await PortableProofOfWorkSolver().solve(puzzle) }
    task.cancel()
    await #expect(throws: ProfileHostingError.cancelled) { try await task.value }
    #expect(throws: ProfileHostingError.unsolvable("alice")) {
      try ProofOfWorkPuzzle(domain: domain, label: "alice", identityID: Digest(hashing: []),
        requiredBits: 65)
    }
  }

  @Test func policyArithmeticAndValidation() throws {
    func policy(_ base: Int64, _ slope: Int64, _ length: Int64) throws -> HostingPolicy {
      try HostingPolicy(json: FakeHost.json(FakeHost.policy(base: base, slope: slope,
        length: length)).body, domain: domain)
    }
    #expect(try policy(20, 2, 8).requiredBits(for: "alice") == 26)
    #expect(try policy(20, 2, 8).requiredBits(for: "longername") == 20)
    #expect(try policy(0, 0, Int64.max).requiredBits(for: "a") == 0)
    #expect(try policy(Int64.max, 1, 8).requiredBits(for: "a") == nil)
    #expect(try policy(0, Int64.max, 8).requiredBits(for: "a") == nil)
    #expect(try policy(0, 0, Int64.min).requiredBits(for: "a") == nil)
    #expect(try policy(-1, 0, 8).requiredBits(for: "a") == nil)
    #expect(throws: ProfileHostingError.domainMismatch) {
      try HostingPolicy(json: FakeHost.json(FakeHost.policy(domain: "other.example")).body,
        domain: domain)
    }
    #expect(throws: ProfileHostingError.unsupportedAlgorithm("future")) {
      try HostingPolicy(json: FakeHost.json(FakeHost.policy(algorithm: "future")).body,
        domain: domain)
    }
  }

  @Test func strictJSON() throws {
    let valid = #"{"text":"\uD83D\uDE00\n\t\b\f\r\/\\\"","n":18446744073709551615}"#
    let fields = try JSON(Array(valid.utf8)).object()
    #expect(try fields.field("n").unsigned() == UInt64.max)
    #expect(try fields.field("text").string() == "😀\n\t\u{8}\u{c}\r/\\\"")
    #expect(try JSON(Array("-9223372036854775808".utf8)).integer() == Int64.min)
    for text in [#"{"x":1,"\u0078":2}"#, "01", "-01", "1.", "1e", "+1", "NaN",
      "[1,]", #"{"x":1,}"#, #""\uD800""#, #""\uDC00""#, "true false", "\"\n\"",
      String(repeating: "[", count: 18) + "0" + String(repeating: "]", count: 18)] {
      #expect(throws: ProfileHostingError.invalidResponse) { try JSON(Array(text.utf8)) }
    }
    for text in ["18446744073709551616", "1e100000", "1.0", "-1"] {
      #expect(throws: ProfileHostingError.invalidResponse) {
        try JSON(Array(text.utf8)).unsigned()
      }
    }
    #expect(try JSON(Array("[true,false,null,-0,1.5e+10]".utf8)).array().count == 5)
    #expect(throws: ProfileHostingError.invalidResponse) { try JSON([34, 0xc0, 0x80, 34]) }
    #expect(throws: ProfileHostingError.invalidResponse) {
      try JSON(Array(repeating: 32, count: JSON.maximumBytes + 1))
    }
  }

  @Test func unknownProblems() throws {
    let response = FakeHost.json(["type": "urn:diem:profile-hosting:future",
      "title": "Future", "status": 429, "detail": "Wait",
      "labels": [["label": "alice", "reason": "future", "requiredBits": 12]]],
      status: 429, headers: ["rEtRy-AfTeR": "123"])
    let problem = try HostingProblem(response: response)
    #expect(problem.code == .unknown("future"))
    #expect(problem.retryAfter == 123)
    #expect(problem.labels.first?.requiredBits == 12)
    #expect(response.header("RETRY-AFTER") == "123")
  }
}
