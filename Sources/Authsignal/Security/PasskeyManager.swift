import AuthenticationServices
import Foundation

class PasskeyManager: NSObject {
  private var continuation: CheckedContinuation<ASAuthorization, Error>?
  private var controller: ASAuthorizationController?

  func register(
    relyingPartyID: String,
    challenge: String,
    userID: String,
    displayName: String
  ) async -> AuthsignalResponse<PasskeyRegistrationCredential>
  {
    guard #available(iOS 15.0, *) else {
      return AuthsignalResponse(error: "iOS version not supported")
    }

    guard let challengeData = Data(base64URLEncoded: challenge) else {
      return AuthsignalResponse(error: "error encoding challenge")
    }

    let userData = Data(userID.utf8)

    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
      relyingPartyIdentifier: relyingPartyID)

    let request = provider.createCredentialRegistrationRequest(
      challenge: challengeData,
      name: displayName,
      userID: userData
    )

    let controller = ASAuthorizationController(authorizationRequests: [request])
    controller.delegate = self
    controller.presentationContextProvider = self

    self.controller = controller

    do {
      let authorization = try await withCheckedThrowingContinuation { continuation in
        self.continuation = continuation

        controller.performRequests()
      }

      guard
        let credential = authorization.credential
          as? ASAuthorizationPlatformPublicKeyCredentialRegistration
      else {
        return AuthsignalResponse(error: "error unwrapping credential")
      }

      let credentialId = credential.credentialID.base64URLEncodedString()

      let registrationCredential = PasskeyRegistrationCredential(
        id: credentialId,
        rawId: credentialId,
        type: "public-key",
        authenticatorAttachment: "cross-platform",
        response: PasskeyRegistrationCredentialResponse(
          attestationObject: credential.rawAttestationObject?.base64URLEncodedString(),
          clientDataJSON: credential.rawClientDataJSON.base64EncodedString()
        )
      )

      return AuthsignalResponse(data: registrationCredential)
    } catch {
      Logger.error("Registration error: \(error)")
      
      return AuthsignalResponse(error: error.localizedDescription)
    }
  }

  func auth(
    relyingPartyID: String,
    challenge: String,
    autofill: Bool
  ) async -> AuthsignalResponse<PasskeyAuthenticationCredential>
  {
    guard #available(iOS 15.0, *) else {
      return AuthsignalResponse(error: "iOS version not supported")
    }
    
    if autofill, #unavailable(iOS 16.0) {
      return AuthsignalResponse(error: "iOS version not supported for autofill")
    }

    if self.continuation != nil || self.controller != nil {
      return AuthsignalResponse(error: "credential assertion already in progress")
    }

    guard let challengeData = Data(base64URLEncoded: challenge) else {
      return AuthsignalResponse(error: "error encoding challenge")
    }

    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
      relyingPartyIdentifier: relyingPartyID)

    let request = provider.createCredentialAssertionRequest(challenge: challengeData)

    let controller = ASAuthorizationController(authorizationRequests: [request])

    controller.delegate = self
    controller.presentationContextProvider = self

    self.controller = controller

    do {
      let authorization = try await withCheckedThrowingContinuation { continuation in
        self.continuation = continuation

        if #available(iOS 16.0, *), autofill {
          controller.performAutoFillAssistedRequests()
        } else {
          controller.performRequests()
        }
      }

      self.controller = nil
      self.continuation = nil

      guard
        let credential = authorization.credential
          as? ASAuthorizationPlatformPublicKeyCredentialAssertion
      else {
        return AuthsignalResponse(error: "error unwrapping credential")
      }

      let credentialId = credential.credentialID.base64URLEncodedString()

      let authenticationCredential = PasskeyAuthenticationCredential(
        id: credentialId,
        rawId: credentialId,
        type: "public-key",
        authenticatorAttachment: "cross-platform",
        response: PasskeyAuthenticationCredentialResponse(
          authenticatorData: credential.rawAuthenticatorData.base64URLEncodedString(),
          clientDataJSON: credential.rawClientDataJSON.base64EncodedString(),
          signature: credential.signature.base64URLEncodedString(),
          userHandle: String(decoding: credential.userID, as: UTF8.self)
        )
      )

      return AuthsignalResponse(data: authenticationCredential)
    } catch {
      self.controller = nil
      self.continuation = nil
      
      Logger.error("Authentication error: \(error)")
      
      return AuthsignalResponse(error: error.localizedDescription)
    }
  }

  func cancelRequest() {
    if #available(iOS 16.0, *) {
      self.controller?.cancel()
    }
  }
}

extension PasskeyManager: ASAuthorizationControllerDelegate,
  ASAuthorizationControllerPresentationContextProviding
{
  func authorizationController(
    controller: ASAuthorizationController,
    didCompleteWithAuthorization authorization: ASAuthorization
  ) {
    continuation?.resume(returning: authorization)
  }

  func authorizationController(
    controller: ASAuthorizationController, didCompleteWithError error: Error
  ) {
    continuation?.resume(throwing: error)
  }

  func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
    let keyWindow = UIApplication
      .shared
      .connectedScenes
      .compactMap { $0 as? UIWindowScene }
      .flatMap { $0.windows }
      .first { $0.isKeyWindow }

    return keyWindow!
  }
}
