import AuthenticationServices
import Foundation

class PasskeyManager: NSObject {
  private var continuation: CheckedContinuation<ASAuthorization, Error>?
  private var controller: ASAuthorizationController?
  
  func register(relyingPartyID: String, challenge: String, userID: String, displayName: String) async -> PasskeyRegistrationCredential? {
    guard #available(iOS 15.0, *) else {
      return nil
    }
    
    guard let challengeData = Data(base64URLEncoded: challenge) else {
      return nil
    }
    
    let userData = Data(userID.utf8)
    
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: relyingPartyID)
    
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
      
      guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration else {
        return nil
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
      
      return registrationCredential
    } catch {
      print("Registration error: \(error)")
    }
    
    return nil
  }
  
  func auth(relyingPartyID: String, challenge: String, autofill: Bool) async -> PasskeyAuthenticationCredential? {
    guard #available(iOS 15.0, *) else {
      return nil
    }
    
    if self.continuation != nil || self.controller != nil {
      return nil
    }
    
    guard let challengeData = Data(base64URLEncoded: challenge) else {
      return nil
    }
    
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: relyingPartyID)
    
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
      
      guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
        return nil
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
      
      return authenticationCredential
    } catch {
      print("Auth error: \(error)")
    }
    
    return nil
  }
  
  func cancelRequest() {
    if #available(iOS 16.0, *) {
      self.controller?.cancel()
    }
  }
}

extension PasskeyManager: ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
  func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
    continuation?.resume(returning: authorization)
  }

  func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
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
