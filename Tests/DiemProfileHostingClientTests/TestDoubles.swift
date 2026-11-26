import Diem
import DiemProfileHostingClient

actor StubHTTP: HostingHTTPClient {
  let response: HostingHTTPResponse
  var requests: [HostingHTTPRequest] = []
  init(_ response: HostingHTTPResponse) { self.response = response }
  func send(_ request: HostingHTTPRequest) -> HostingHTTPResponse {
    requests.append(request)
    return response
  }
}

actor RecordingSolver: ProofOfWorkSolver {
  var puzzles: [ProofOfWorkPuzzle] = []
  var bad: Bool
  init(bad: Bool = false) { self.bad = bad }
  func solve(_ puzzle: ProofOfWorkPuzzle) async throws -> [UInt8] {
    puzzles.append(puzzle)
    return bad ? [] : try await PortableProofOfWorkSolver().solve(puzzle)
  }
}
