import Foundation

class BaseAPIClient {
  let baseURL: String
  let basicAuth: String

  public init(tenantID: String, baseURL: String) {
    self.baseURL = baseURL
    self.basicAuth = "Basic \(Data( "\(tenantID):".utf8).base64URLEncodedString())"
  }

  func challenge(action: String) async -> AuthsignalResponse<ChallengeResponse> {
    let url = "\(baseURL)/client/challenge"

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
        let responseError = json?["error"] as? String
        let responseErrorCode = json?["errorCode"] as? String
        let responseErrorDescription = json?["errorDescription"] as? String
        
        if let responseError = responseError {
          Logger.error("API response error: \(responseError)")
        }
        
        if let responseErrorCode = responseErrorCode {
          Logger.error("API response error code: \(responseErrorCode)")
        }

        if let responseErrorDescription = responseErrorDescription {
          Logger.error("API response error description: \(responseErrorDescription)")
        }
        
        let error = !(responseErrorDescription ?? "").isEmpty ? responseErrorDescription : responseError
        let errorCode = responseErrorCode
        
        return AuthsignalResponse(error: error ?? "unexpected_error", errorCode: errorCode)
      }

      let decoder = JSONDecoder()

      let decoded = try? decoder.decode(T.self, from: data)
      
      if let decoded = decoded {
        return AuthsignalResponse(data: decoded)
      } else {
        return AuthsignalResponse(error: "Decoding error.")
      }
    } catch {
      Logger.error("API request error: \(error).")

      return AuthsignalResponse(error: error.localizedDescription)
    }
  }
  
  lazy var defaultDeviceID = {
    let defaultDeviceLocalKey = "@as_device_id"
    
    if let defaultDeviceID = UserDefaults.standard.string(forKey: defaultDeviceLocalKey) {
      return defaultDeviceID
    }
    
    let newDefaultDeviceID = UUID().uuidString
    
    UserDefaults.standard.set(newDefaultDeviceID, forKey: defaultDeviceLocalKey)
    
    return newDefaultDeviceID
  }
}
