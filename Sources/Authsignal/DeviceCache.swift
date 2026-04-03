import Foundation

public class DeviceCache {
  private var _deviceID: String? = nil

  public func getDefaultDeviceID() async -> String {
    if (_deviceID != nil) {
      return _deviceID!
    }

    let defaultDeviceLocalKey = "@as_device_id"

    if let defaultDeviceID = UserDefaults.standard.string(forKey: defaultDeviceLocalKey) {
      return defaultDeviceID
    }

    let newDefaultDeviceID = UUID().uuidString

    UserDefaults.standard.set(newDefaultDeviceID, forKey: defaultDeviceLocalKey)

    return newDefaultDeviceID
  }

  public static let shared = DeviceCache()
}
