import Foundation
import Logging

class DeviceAPI {
  private let baseUrl: String?

  private let logger = Logger(label: "com.authsignal.DeviceAPI")

  init() {
    self.baseUrl = Bundle.main.object(forInfoDictionaryKey: "AuthsignalURL") as? String

    if self.baseUrl == nil {
      logger.warning("AuthsignalURL not configured.")
    }
  }

  func addCredential(accessToken: String, publicKey: String) async -> Bool {
    guard let baseUrl = baseUrl else {
      return false
    }

    let url = URL(string: "\(baseUrl)/add-credential")!
    let body = ["publicKey": publicKey]

    var request = URLRequest(url: url)
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
    request.httpMethod = "POST"
    request.httpBody = try? JSONSerialization.data(withJSONObject: body)

    do {
      let (data, _) = try await URLSession.shared.data(for: request)

      let responseJSON = try? JSONSerialization.jsonObject(with: data, options: [])

      if let responseJSON = responseJSON as? [String: Any] {
        if let userAuthenticatorId = responseJSON["userAuthenticatorId"] {
          logger.info("Credential added for authenticator: \(userAuthenticatorId)")

          return true
        }
      }

      return false
    } catch {
      logger.error("Error adding credential: \(error).")

      return false
    }
  }

  func removeCredential(challengeId: String, publicKey: String, signature: String) async -> Bool {
    guard let baseUrl = baseUrl else {
      return false
    }

    let url = URL(string: "\(baseUrl)/remove-credential")!
    let body = ["sessionToken": challengeId, "publicKey": publicKey, "signature": signature]

    var request = URLRequest(url: url)
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpMethod = "POST"
    request.httpBody = try? JSONSerialization.data(withJSONObject: body)

    do {
      let (data, _) = try await URLSession.shared.data(for: request)

      let responseJSON = try? JSONSerialization.jsonObject(with: data, options: [])

      if let responseJSON = responseJSON as? [String: Any] {
        if let userAuthenticatorId = responseJSON["removedAuthenticatorId"] {
          logger.info("Credential removed for authenticator: \(userAuthenticatorId)")

          return true
        }
      }

      return false
    } catch {
      logger.error("Error removing credential: \(error).")

      return false
    }
  }

  public func startChallenge(publicKey: String) async -> String? {
    guard let baseUrl = baseUrl else {
      return nil
    }

    let url = URL(string: "\(baseUrl)/start-challenge")!
    let body = ["publicKey": publicKey]

    var request = URLRequest(url: url)
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpMethod = "POST"
    request.httpBody = try? JSONSerialization.data(withJSONObject: body)

    do {
      let (data, _) = try await URLSession.shared.data(for: request)

      let responseJSON = try? JSONSerialization.jsonObject(with: data, options: [])

      if let responseJSON = responseJSON as? [String: Any] {
        if let challengeId = responseJSON["sessionToken"] as? String {
          logger.info("Challenge started: \(challengeId)")

          return challengeId
        }
      }

      return nil
    } catch {
      logger.error("Error starting challenge: \(error).")

      return nil
    }
  }

  public func getChallenge(publicKey: String) async -> String? {
    guard let baseUrl = baseUrl else {
      return nil
    }

    let url = URL(string: "\(baseUrl)/get-challenge")!
    let body = ["publicKey": publicKey]

    var request = URLRequest(url: url)
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpMethod = "POST"
    request.httpBody = try? JSONSerialization.data(withJSONObject: body)

    do {
      let (data, _) = try await URLSession.shared.data(for: request)

      let responseJSON = try? JSONSerialization.jsonObject(with: data, options: [])

      if let responseJSON = responseJSON as? [String: Any] {
        if let challengeId = responseJSON["sessionToken"] as? String {
          logger.info("Challenge found: \(challengeId)")

          return challengeId
        }
      }

      return nil
    } catch {
      logger.error("Error getting challenge: \(error).")

      return nil
    }
  }

  public func updateChallenge(
    challengeId: String, publicKey: String, signature: String, approved: Bool
  ) async {
    guard let baseUrl = baseUrl else {
      return
    }

    let url = URL(string: "\(baseUrl)/update-challenge")!

    let body: [String: Any] = [
      "publicKey": publicKey,
      "sessionToken": challengeId,
      "approved": approved,
      "signature": signature,
    ]

    var request = URLRequest(url: url)
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpMethod = "POST"
    request.httpBody = try? JSONSerialization.data(withJSONObject: body)

    do {
      let (_, _) = try await URLSession.shared.data(for: request)
    } catch {
      logger.error("Error updating challenge: \(error).")
    }
  }
}

@available(iOS, deprecated: 15.0, message: "Use the built-in API instead")
extension URLSession {
  func data(from request: URLRequest) async throws -> (Data, URLResponse) {
    try await withCheckedThrowingContinuation { continuation in
      let task = self.dataTask(
        with: request,
        completionHandler: { data, response, error in
          guard let data = data, let response = response else {
            let error = error ?? URLError(.badServerResponse)
            return continuation.resume(throwing: error)
          }

          continuation.resume(returning: (data, response))
        })

      task.resume()
    }
  }
}
