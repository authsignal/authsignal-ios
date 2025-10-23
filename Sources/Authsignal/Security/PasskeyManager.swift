import AuthenticationServices
import Foundation

class PasskeyManager: NSObject {
  private var continuation: CheckedContinuation<ASAuthorization, Error>?
  private var controller: ASAuthorizationController?

  func register(
    relyingPartyId: String,
    challenge: String,
    userId: String,
    displayName: String,
    existingCredentialIds: [String]
  ) async -> AuthsignalResponse<PasskeyRegistrationCredential>
  {
    guard #available(iOS 15.0, *) else {
      return AuthsignalResponse(error: "iOS version not supported.")
    }

    guard let challengeData = Data(base64URLEncoded: challenge) else {
      return AuthsignalResponse(error: "Error encoding challenge.")
    }
    
    if self.continuation != nil || self.controller != nil {
      return AuthsignalResponse(error: "Credential registration already in progress.")
    }

    let userData = Data(userId.utf8)

    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: relyingPartyId)

    
    let request = provider.createCredentialRegistrationRequest(
      challenge: challengeData,
      name: displayName,
      userID: userData
    )
    
    if #available(iOS 17.4, *) {
      request.excludedCredentials = existingCredentialIds.compactMap {
        Data(base64URLEncoded: $0).map {
          ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0)
        }
      }
    }

    let controller = ASAuthorizationController(authorizationRequests: [request])
    
    controller.delegate = self
    controller.presentationContextProvider = self

    self.controller = controller

    do {
      let authorization = try await withCheckedThrowingContinuation { continuation in
        self.continuation = continuation

        controller.performRequests()
      }
      
      self.controller = nil
      self.continuation = nil

      guard
        let credential = authorization.credential
          as? ASAuthorizationPlatformPublicKeyCredentialRegistration
      else {
        return AuthsignalResponse(error: "Error unwrapping credential.")
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
      self.controller = nil
      self.continuation = nil
      
      if #available(iOS 18.0, *),
         let authError = error as? ASAuthorizationError,
         authError.code == .matchedExcludedCredential {
        return AuthsignalResponse(
          error: "An existing credential is already available for this device.",
          errorCode: SdkErrorCodes.matchedExcludedCredential
        )
      }
      
      Logger.error("Registration error: \(error)")
      
      return AuthsignalResponse(error: error.localizedDescription)
    }
  }

  func auth(
    relyingPartyId: String,
    challenge: String,
    autofill: Bool,
    preferImmediatelyAvailableCredentials: Bool
  ) async -> AuthsignalResponse<PasskeyAuthenticationCredential>
  {
    guard #available(iOS 15.0, *) else {
      return AuthsignalResponse(error: "iOS version not supported.")
    }
    
    if autofill, #unavailable(iOS 16.0) {
      return AuthsignalResponse(error: "iOS version not supported for autofill.")
    }

    if self.continuation != nil || self.controller != nil {
      return AuthsignalResponse(error: "Credential assertion already in progress.")
    }

    guard let challengeData = Data(base64URLEncoded: challenge) else {
      return AuthsignalResponse(error: "Error encoding challenge.")
    }

    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
      relyingPartyIdentifier: relyingPartyId)
  
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
        } else if #available(iOS 16.0, *), preferImmediatelyAvailableCredentials {
          controller.performRequests(options: .preferImmediatelyAvailableCredentials)
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
        return AuthsignalResponse(error: "Error unwrapping credential.")
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
    } catch ASAuthorizationError.canceled {
      self.controller = nil
      self.continuation = nil
      
      return AuthsignalResponse(
        error: "The request was canceled by the user or the device has no passkeys available.",
        errorCode: SdkErrorCodes.userCanceled
      )
    } catch {
      self.controller = nil
      self.continuation = nil
      
      Logger.error("Passkey authentication error: \(error)")

      return AuthsignalResponse(error: error.localizedDescription)
    }
  }

  func cancelRequest() {
    if #available(iOS 16.0, *) {
      self.controller?.cancel()
    }
  }
}

@available(iOSApplicationExtension, unavailable)
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
