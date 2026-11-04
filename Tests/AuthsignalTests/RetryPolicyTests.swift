import XCTest
@testable import Authsignal

final class RetryPolicyTests: XCTestCase {
  let policy = RetryPolicy.default

  func testFailuresBeforeTheRequestReachesTheServerAreNotSent() {
    for code: URLError.Code in [.notConnectedToInternet, .cannotFindHost, .cannotConnectToHost, .dnsLookupFailed] {
      XCTAssertEqual(RetryPolicy.outcome(error: URLError(code)), .notSent, "\(code)")
    }
  }

  func testTimeoutsAndDroppedConnectionsHaveAnUnknownOutcome() {
    for code: URLError.Code in [.timedOut, .networkConnectionLost, .secureConnectionFailed] {
      XCTAssertEqual(RetryPolicy.outcome(error: URLError(code)), .unknown, "\(code)")
    }
  }

  func testStatusCodes() {
    XCTAssertNil(RetryPolicy.outcome(statusCode: 200))
    XCTAssertEqual(RetryPolicy.outcome(statusCode: 408), .rejected)
    XCTAssertEqual(RetryPolicy.outcome(statusCode: 429, retryAfter: "1"), .rejected)
    XCTAssertEqual(RetryPolicy.outcome(statusCode: 429), .final)
    XCTAssertEqual(RetryPolicy.outcome(statusCode: 500), .unknown)
    XCTAssertEqual(RetryPolicy.outcome(statusCode: 502), .unknown)
    XCTAssertEqual(RetryPolicy.outcome(statusCode: 503), .unknown)
    XCTAssertEqual(RetryPolicy.outcome(statusCode: 504), .unknown)
    XCTAssertEqual(RetryPolicy.outcome(statusCode: 400), .final)
    XCTAssertEqual(RetryPolicy.outcome(statusCode: 401), .final)
    XCTAssertEqual(RetryPolicy.outcome(statusCode: 404), .final)
  }

  func testCancellationIsNeverRetried() {
    XCTAssertEqual(RetryPolicy.outcome(error: URLError(.cancelled)), .final)
    XCTAssertEqual(RetryPolicy.outcome(error: CancellationError()), .final)
  }

  func testDecisionTable() {
    let table: [(outcome: RetryPolicy.Outcome, replaySafe: Bool, retry: Bool)] = [
      (.notSent, true, true),
      (.notSent, false, true),
      (.rejected, true, true),
      (.rejected, false, true),
      (.unknown, true, true),
      (.unknown, false, false),
      (.final, true, false),
      (.final, false, false),
    ]

    for row in table {
      XCTAssertEqual(
        policy.shouldRetry(row.outcome, replaySafe: row.replaySafe), row.retry,
        "\(row.outcome), replaySafe: \(row.replaySafe)")
    }
  }

  func testBackoffDoublesWithJitter() {
    for _ in 0..<100 {
      XCTAssertTrue((0.25...0.5).contains(policy.delay(beforeRetry: 1, retryAfter: nil)!))
      XCTAssertTrue((0.5...1).contains(policy.delay(beforeRetry: 2, retryAfter: nil)!))
    }
  }

  func testBackoffIsCappedAtMaxDelay() {
    XCTAssertLessThanOrEqual(policy.delay(beforeRetry: 10, retryAfter: nil)!, policy.maxDelay)
  }

  func testRetryAfterIsHonouredUpToMaxDelay() {
    XCTAssertEqual(policy.delay(beforeRetry: 1, retryAfter: "2"), 2)
    XCTAssertEqual(policy.delay(beforeRetry: 1, retryAfter: "5"), 5)
    XCTAssertNil(policy.delay(beforeRetry: 1, retryAfter: "6"))
  }
}
