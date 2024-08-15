import Foundation

class SMSAPIClient: BaseAPIClient {
  func enrollSMS(
    token: String,
    phoneNumber: String
  ) async -> AuthsignalResponse<EnrollResponse> {
    let url = "\(baseURL)/client/user-authenticators/sms"

    let body = AddSMSAuthenticatorRequest(phoneNumber: phoneNumber)

    return await postRequest(url: url, body: body, token: token)
  }
  
  func challengeSMS(
    token: String
  ) async -> AuthsignalResponse<ChallengeResponse> {
    let url = "\(baseURL)/client/challenge/sms"

    return await postRequest(url: url, token: token)
  }

  func verifySMS(
    token: String,
    code: String
  ) async -> AuthsignalResponse<VerifyResponse> {
    let url = "\(baseURL)/client/verify/sms"

    let body = VerifyRequest(verificationCode: code)

    return await postRequest(url: url, body: body, token: token)
  }
}
