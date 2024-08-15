import Foundation

class BaseApiClient {
  let baseUrl: String
  let basicAuth: String

  public init(tenantId: String, baseUrl: String) {
    self.baseUrl = baseUrl
    self.basicAuth = "Basic \(Data( "\(tenantId):".utf8).base64URLEncodedString())"
  }

  func challenge(action: String) async -> AuthsignalResponse<ChallengeResponse> {
    let url = "\(baseUrl)/client/challenge"

    let body = ChallengeRequest(action: action)

    return await postRequest(url: url, body: body)
  }

  func getRequest<T: Decodable>(url: String, token: String? = nil) async -> AuthsignalResponse<T> {
    var request = URLRequest(url: URL(string: url)!)

    request.httpMethod = "GET"
    
    if let token = token {
      request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    } else {
      request.setValue(basicAuth, forHTTPHeaderField: "Authorization")
    }
  
    return await performRequest(request: request)
  }

  func postRequest<T: Decodable>(url: String, token: String) async -> AuthsignalResponse<T> {
    var request = URLRequest(url: URL(string: url)!)

    request.httpMethod = "POST"
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

    return await performRequest(request: request)
  }
  
  func postRequest<T: Decodable, TBody: Encodable>(url: String, body: TBody, token: String? = nil)
    async -> AuthsignalResponse<T>
  {
    var request = URLRequest(url: URL(string: url)!)

    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    
    if let token = token {
      request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    } else {
      request.setValue(basicAuth, forHTTPHeaderField: "Authorization")
    }

    let encoder = JSONEncoder()

    if let encodedBody = try? encoder.encode(body) {
      request.httpBody = encodedBody
    }

    return await performRequest(request: request)
  }

  private func performRequest<T: Decodable>(request: URLRequest) async -> AuthsignalResponse<T> {
    do {
      let (data, response) = try await URLSession.shared.data(for: request)

      let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]

      if let httpResponse = response as? HTTPURLResponse,
        httpResponse.statusCode != 200
      {
        let error = json?["error"] as? String
        let errorMessage = json?["message"] as? String
        let errorDescription = json?["errorDescription"] as? String
        
        if let error = error {
          Logger.error("Error: \(error)")
        }

        if let errorMessage = errorMessage {
          Logger.error("Error message: \(errorMessage)")
        }

        if let errorDescription = errorDescription {
          Logger.error("Error description: \(errorDescription)")
        }
        
        let rawError = String(data: data, encoding: String.Encoding.utf8)
        
        return AuthsignalResponse(error: errorDescription ?? errorMessage ?? error ?? rawError ?? "api error")
      }

      let decoder = JSONDecoder()

      let decoded = try? decoder.decode(T.self, from: data)
      
      if let decoded = decoded {
        return AuthsignalResponse(data: decoded)
      } else {
        return AuthsignalResponse(error: "decoding error")
      }
    } catch {
      Logger.error("Request error: \(error).")

      return AuthsignalResponse(error: error.localizedDescription)
    }
  }
  
  lazy var defaultDeviceId = {
    let defaultDeviceLocalKey = "@as_device_id"
    
    if let defaultDeviceId = UserDefaults.standard.string(forKey: defaultDeviceLocalKey) {
      return defaultDeviceId
    }
    
    let newDefaultDeviceId = UUID().uuidString
    
    UserDefaults.standard.set(newDefaultDeviceId, forKey: defaultDeviceLocalKey)
    
    return newDefaultDeviceId
  }
}
