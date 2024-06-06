# tech_shield 
### wrapper for USB-dongle-devices (yubikeys/nitrokeys)
 
## Overview:

This GitHub project is maintained by TechShield and serves as a wrapper for the proposed crypto abstraction layer, facilitating access to a specific hardware security module (HSM) on attached USB-dongles (Yubikey). These dongles support secure key storage.

## Objective:

Our goal is to provice a user-friendly and secure way to access the functionality of the HSM without needing to worry about complex implementation details. The wrapper aims to simplify the use of the HSM for developers and provice a reliable abstraction layer.

## Features:

- Enables access to the HSM through a user-friendly abstraction layer.
- Supports secure storage and retrieval of keys.
- Provides functions for data encryption and decryption.
- Implements security mechanisms to ensure the confidentiality and integrity of data.

## Installation:

**In order for our solution to work, it is required that OpenSSL has been installed successfully.**

### Windows
[Download OpenSSL for Windows](https://www.heise.de/download/product/win32-openssl-47316/download/danke?id=eb9acc71-f52c-4329-a3cf-cf9bd9172d8c)

Make sure to set the environment variables correctly, e.g.: 

```sh
setx OPENSSL_DIR "C:\Program Files\OpenSSL-Win64"
setx OPENSSL_INCLUDE_DIR "C:\Program Files\OpenSSL-Win64\include"
setx OPENSSL_LIB_DIR "C:\Program Files\OpenSSL-Win64\lib"
```

### Linux

```
sudo apt-get install libssl-dev
```

## Usage:

(under construction)

## Contribution:

We welcome contributions from the community. If you find any bugs, have suggestions for improvements or wish to add new features, feel free to create a pull request.

## License:

This project is released under the MIT License. For more information please refer to the [__LICENSE__](./LICENSE.md) file.

## Contact:

For any questions or suggestions, feel free to reach out to us using the GitHub issue feature or by sending an email to our team.

Thank you for your interest in our project!

TechShield
