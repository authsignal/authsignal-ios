public enum KeychainAccess {
  case afterFirstUnlock
  case afterFirstUnlockThisDeviceOnly
  case whenUnlocked
  case whenUnlockedThisDeviceOnly
  case whenPasscodeSetThisDeviceOnly
}
