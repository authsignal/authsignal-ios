import Foundation

class EmailAPIClient: BaseAPIClient {
  func enrollEmail(
    token: String,
    email: String
  ) async -> AuthsignalResponse<EnrollResponse> {
    let url = "\(baseURL)/client/user-authenticators/email-otp"

    let body = AddEmailAuthenticatorRequest(email: email)

    return await postRequest(url: url, body: body, token: token)
  }
  
  func challengeEmail(
    token: String
  ) async -> AuthsignalResponse<ChallengeResponse> {
    let url = "\(baseURL)/client/challenge/email-otp"

    return await postRequest(url: url, token: token)
  }

  func verifyEmail(
    token: String,
    code: String
  ) async -> AuthsignalResponse<VerifyResponse> {
    let url = "\(baseURL)/client/verify/email-otp"

    let body = VerifyRequest(verificationCode: code)

    return await postRequest(url: url, body: body, token: token)
  }
}
