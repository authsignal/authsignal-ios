import Foundation

class EmailApiClient: BaseApiClient {
  func enrollEmail(
    token: String,
    email: String
  ) async -> AuthsignalResponse<EnrollResponse> {
    let url = "\(baseUrl)/client/user-authenticators/email-otp"

    let body = AddEmailAuthenticatorRequest(email: email)

    return await postRequest(url: url, body: body, token: token)
  }
  
  func challengeEmail(
    token: String
  ) async -> AuthsignalResponse<ChallengeResponse> {
    let url = "\(baseUrl)/client/challenge/email-otp"

    return await postRequest(url: url, token: token)
  }

  func verifyEmail(
    token: String,
    code: String
  ) async -> AuthsignalResponse<VerifyResponse> {
    let url = "\(baseUrl)/client/verify/email-otp"

    let body = VerifyRequest(verificationCode: code)

    return await postRequest(url: url, body: body, token: token)
  }
}
