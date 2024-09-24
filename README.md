# Authsignal iOS

Check out our [official iOS documentation](https://docs.authsignal.com/sdks/client/ios).

## Installation

#### Cocoapods

Add Authsignal to your Podfile:

```rb
pod 'Authsignal', '~> 1.0.10'
```

#### Swift Package Manager

Add authsignal-ios to the dependencies value of your Package.swift.

```swift
dependencies: [
    .package(url: "https://github.com/authsignal/authsignal-ios.git", from: "1.0.10")
]
```

## Initialization

```swift
import Authsignal
...

let authsignal = Authsignal(clientID: "YOUR_TENANT_ID", baseURL: "YOUR_REGION_BASE_URL")
```

You can find your client or tenant ID in the [Authsignal Portal](https://portal.authsignal.com/organisations/tenants/api).

You must specify the correct base URL for your tenant's region.

| Region      | Base URL                         |
| ----------- | -------------------------------- |
| US (Oregon) | https://api.authsignal.com/v1    |
| AU (Sydney) | https://au.api.authsignal.com/v1 |
| EU (Dublin) | https://eu.api.authsignal.com/v1 |

## Usage

### Passkeys

For more detailed info on how add passkeys to your app using Authsignal, check out our [official passkey documentation for iOS](https://docs.authsignal.com/sdks/client/ios#passkeys).

### Push auth

To see how to add push authentication to your app using Authsignal, see our [official push documentation for iOS](https://docs.authsignal.com/sdks/client/ios#push).
