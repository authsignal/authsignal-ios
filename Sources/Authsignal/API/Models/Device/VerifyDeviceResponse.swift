public struct VerifyDeviceResponse: Codable {
    public let token: String
    public let userId: String
    public let userAuthenticatorId: String
    public let username: String?
}
