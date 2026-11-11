import Foundation

class BaseAPIClient {
  let baseURL: String
  let tenantID: String
  let basicAuth: String
  let deviceID: String?
  var retryPolicy: RetryPolicy
  var requestTimeout: TimeInterval = 20

  public init(tenantID: String, baseURL: String, deviceID: String? = nil, retries: Int = 2) {
    self.baseURL = baseURL
    self.tenantID = tenantID
    self.basicAuth = "Basic \(Data( "\(tenantID):".utf8).base64URLEncodedString())"
    self.deviceID = deviceID
    self.retryPolicy = RetryPolicy(maxRetries: retries)
  }

  func challenge(action: String? = nil, token: String? = nil) async -> AuthsignalResponse<ChallengeResponse> {
    let url = "\(baseURL)/client/challenge"

    let body = ChallengeRequest(action: action)

    return await postRequest(url: url, body: body, token: token)
  }
  

  func getRequest<T: Decodable>(url: String, token: String? = nil, headers: [String: String] = [:]) async -> AuthsignalResponse<T> {
    var request = URLRequest(url: URL(string: url)!)

    request.httpMethod = "GET"

    if let token = token {
      request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    } else {
      request.setValue(basicAuth, forHTTPHeaderField: "Authorization")
    }

    headers.forEach { name, value in
      request.setValue(value, forHTTPHeaderField: name)
    }

    applyDefaultHeaders(to: &request)

    return await performRequest(request: request)
  }

  func postRequest<T: Decodable>(url: String, token: String? = nil)
    async -> AuthsignalResponse<T>
  {
    var request = URLRequest(url: URL(string: url)!)

    request.httpMethod = "POST"

    if let token = token {
      request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    } else {
      request.setValue(basicAuth, forHTTPHeaderField: "Authorization")
    }

    applyDefaultHeaders(to: &request)

    return await performRequest(request: request)
  }

  func postRequest<T: Decodable, TBody: Encodable>(
    url: String,
    body: TBody,
    token: String? = nil
  ) async -> AuthsignalResponse<T> {
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

    applyDefaultHeaders(to: &request)

    return await performRequest(request: request)
  }

  func patchRequest<T: Decodable, TBody: Encodable>(url: String, body: TBody, token: String? = nil)
    async -> AuthsignalResponse<T>
  {
    var request = URLRequest(url: URL(string: url)!)

    request.httpMethod = "PATCH"
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

    applyDefaultHeaders(to: &request)

    return await performRequest(request: request)
  }

  private func applyDefaultHeaders(to request: inout URLRequest) {
    AuthsignalRequestMetadata.headers(tenantID: tenantID).forEach { name, value in
      request.setValue(value, forHTTPHeaderField: name)
    }
  }

  private func performRequest<T: Decodable>(request: URLRequest) async -> AuthsignalResponse<T> {
    do {
      let (data, response) = try await send(request: request)

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

        if httpResponse.statusCode == 404 && (error?.isEmpty ?? true) {
          return AuthsignalResponse(
            error: "API endpoint not found. Ensure your Authsignal base URL is valid.",
            errorCode: "api_error"
          )
        }
        
        return AuthsignalResponse(error: error ?? "Unexpected error.", errorCode: errorCode)
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

      return AuthsignalResponse(error: error.localizedDescription, errorCode: "network_error")
    }
  }

  private func send(request: URLRequest) async throws -> (Data, URLResponse) {
    var request = request
    request.timeoutInterval = requestTimeout

    var retries = 0

    while true {
      let result: Result<(Data, URLResponse), Error>

      do {
        result = .success(try await URLSession.shared.data(for: request))
      } catch {
        result = .failure(error)
      }

      guard let (outcome, delay) = retryPolicy.retry(retries + 1, of: request, after: result) else {
        return try result.get()
      }

      retries += 1

      Logger.info(
        "Retrying \(request.httpMethod ?? "") \(request.url?.path ?? "") in \(String(format: "%.2f", delay))s "
          + "after outcome \(outcome) (retry \(retries) of \(retryPolicy.maxRetries))."
      )

      try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
    }
  }
}
