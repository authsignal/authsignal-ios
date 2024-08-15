import Foundation

class SmsApiClient: BaseApiClient {
  func enrollSms(
    token: String,
    phoneNumber: String
  ) async -> AuthsignalResponse<EnrollResponse> {
    let url = "\(baseUrl)/client/user-authenticators/sms"

    let body = AddSmsAuthenticatorRequest(phoneNumber: phoneNumber)

    return await postRequest(url: url, body: body, token: token)
  }
  
  func challengeSms(
    token: String
  ) async -> AuthsignalResponse<ChallengeResponse> {
    let url = "\(baseUrl)/client/challenge/sms"

    return await postRequest(url: url, token: token)
  }

  func verifySms(
    token: String,
    code: String
  ) async -> AuthsignalResponse<VerifyResponse> {
    let url = "\(baseUrl)/client/verify/sms"

    let body = VerifyRequest(verificationCode: code)

    return await postRequest(url: url, body: body, token: token)
  }
}
