import Foundation

struct RetryPolicy {
  let maxRetries: Int
  var baseDelay: TimeInterval = 0.5
  var maxDelay: TimeInterval = 5

  enum Outcome: Equatable {
    case notSent
    case rejected
    case unknown
    case final
  }

  static func outcome(of result: Result<(Data, URLResponse), Error>) -> Outcome? {
    switch result {
    case .success(let (_, response)):
      guard let httpResponse = response as? HTTPURLResponse else { return nil }

      return outcome(
        statusCode: httpResponse.statusCode,
        retryAfter: httpResponse.value(forHTTPHeaderField: "Retry-After")
      )
    case .failure(let error):
      return outcome(error: error)
    }
  }

  static func outcome(statusCode: Int, retryAfter: String? = nil) -> Outcome? {
    switch statusCode {
    case 200..<300:
      return nil
    case 408:
      return .rejected
    case 429:
      return retryAfter == nil ? .final : .rejected
    case 500, 502, 503, 504:
      return .unknown
    default:
      return .final
    }
  }

  static func outcome(error: Error) -> Outcome {
    guard let code = (error as? URLError)?.code else { return .final }

    switch code {
    case .notConnectedToInternet,
      .cannotFindHost,
      .cannotConnectToHost,
      .dnsLookupFailed,
      .dataNotAllowed,
      .internationalRoamingOff,
      .callIsActive:
      return .notSent
    case .timedOut,
      .networkConnectionLost,
      .secureConnectionFailed:
      return .unknown
    default:
      return .final
    }
  }

  private static let retrySafeMethods: Set<String> = ["GET", "HEAD", "OPTIONS"]

  // POST endpoints which only issue a fresh challenge, options or nonce, so repeating them is harmless
  private static let retrySafePaths = [
    "/client/challenge",
    "/client/user-authenticators/passkey/registration-options",
    "/client/user-authenticators/passkey/authentication-options",
    "/client/user-authenticators/push/challenge/sign",
  ]

  static func isRetrySafe(_ request: URLRequest) -> Bool {
    if let method = request.httpMethod, retrySafeMethods.contains(method) {
      return true
    }

    guard let path = request.url?.path else { return false }

    return retrySafePaths.contains { path.hasSuffix($0) }
  }

  static func isRetryable(_ outcome: Outcome, request: URLRequest) -> Bool {
    switch outcome {
    case .notSent, .rejected:
      return true
    case .unknown:
      return isRetrySafe(request)
    case .final:
      return false
    }
  }

  func retry(
    _ retry: Int,
    of request: URLRequest,
    after result: Result<(Data, URLResponse), Error>
  ) -> (outcome: Outcome, delay: TimeInterval)? {
    guard retry <= maxRetries,
      let outcome = RetryPolicy.outcome(of: result),
      RetryPolicy.isRetryable(outcome, request: request)
    else {
      return nil
    }

    let retryAfter = (try? result.get().1 as? HTTPURLResponse)?.value(forHTTPHeaderField: "Retry-After")

    guard let delay = delay(beforeRetry: retry, retryAfter: retryAfter) else { return nil }

    return (outcome, delay)
  }

  func delay(beforeRetry retry: Int, retryAfter: String?) -> TimeInterval? {
    if let retryAfter = retryAfter, let seconds = TimeInterval(retryAfter.trimmingCharacters(in: .whitespaces)) {
      return seconds <= maxDelay ? max(seconds, 0) : nil
    }

    let backoff = min(baseDelay * pow(2, Double(retry - 1)), maxDelay)

    return backoff / 2 + .random(in: 0...(backoff / 2))
  }
}
