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

  func shouldRetry(_ outcome: Outcome, replaySafe: Bool) -> Bool {
    switch outcome {
    case .notSent, .rejected:
      return true
    case .unknown:
      return replaySafe
    case .final:
      return false
    }
  }

  func delay(beforeRetry retry: Int, retryAfter: String?) -> TimeInterval? {
    if let retryAfter = retryAfter, let seconds = TimeInterval(retryAfter.trimmingCharacters(in: .whitespaces)) {
      return seconds <= maxDelay ? max(seconds, 0) : nil
    }

    let backoff = min(baseDelay * pow(2, Double(retry - 1)), maxDelay)

    return backoff / 2 + .random(in: 0...(backoff / 2))
  }
}
