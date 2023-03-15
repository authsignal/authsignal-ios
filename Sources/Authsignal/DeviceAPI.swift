import Foundation

class DeviceAPI {
  private let baseUrl: String?
  private let tenantId: String?
  
  init() {
    self.baseUrl = Bundle.main.object(forInfoDictionaryKey: "AuthsignalURL") as? String
    self.tenantId = Bundle.main.object(forInfoDictionaryKey: "AuthsignalTenantID") as? String
    
    if self.baseUrl == nil {
      print("Error enrolling: AuthsignalURL not configured.")
    }
    
    if self.baseUrl == nil {
      print("Error enrolling: AuthsignalTenant not configured.")
    }
  }
  
  func enrollWithAccessToken(_ accessToken: String, publicKey: String) async -> Bool {
    guard let baseUrl = baseUrl else {
      return false
    }
    
    let url = URL(string: "\(baseUrl)/enroll")!
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
          print("Authenticator is enrolled: \(userAuthenticatorId)")
          
          return true
        }
      }
      
      return false
    } catch {
      print("Error enrolling: \(error).")
      
      return false
    }
  }
  
  public func getChallenge(publicKey: String) async -> String? {
    guard let baseUrl = baseUrl else {
      return nil
    }
    
    let url = URL(string: "\(baseUrl)/get-challenge")!
    let body = ["tenantId": tenantId, "publicKey": publicKey]
    
    var request = URLRequest(url: url)
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpMethod = "POST"
    request.httpBody = try? JSONSerialization.data(withJSONObject: body)
    
    do {
      let (data, _) = try await URLSession.shared.data(for: request)
      
      let responseJSON = try? JSONSerialization.jsonObject(with: data, options: [])
      
      if let responseJSON = responseJSON as? [String: Any] {
        if let challengeId = responseJSON["sessionToken"] as? String {
          print("Challenge found: \(challengeId)")
          
          return challengeId
        }
      }
      
      return nil
    } catch {
      print("Error getting challenge: \(error).")
      
      return nil
    }
  }
  
  public func updateChallenge(_ challengeId: String, publicKey: String, signature: String, approved: Bool) async -> Void {
    guard let baseUrl = baseUrl, let tenantId = tenantId else {
      return
    }
    
    let url = URL(string: "\(baseUrl)/update-challenge")!
    
    let body: [String: Any] = [
      "tenantId": tenantId,
      "publicKey": publicKey,
      "sessionToken": challengeId,
      "approved": approved,
      "signature": signature
    ]
    
    var request = URLRequest(url: url)
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpMethod = "POST"
    request.httpBody = try? JSONSerialization.data(withJSONObject: body)
    
    do {
      let (_, _) = try await URLSession.shared.data(for: request)
    } catch {
      print("Error updating challenge: \(error).")
    }
  }
}

@available(iOS, deprecated: 15.0, message: "Use the built-in API instead")
extension URLSession {
  func data(from request: URLRequest) async throws -> (Data, URLResponse) {
    try await withCheckedThrowingContinuation { continuation in
      let task = self.dataTask(with: request, completionHandler: { data, response, error in
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
