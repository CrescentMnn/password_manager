# CLI Password Manager

## Description

This project is a simple password manager written for the command line interface (CLI) to help me learn Rust. It lets users securely store, manage, and retrieve passwords. This project uses the bcrypt library to hash and validate passwords, ensuring that user data is secure.

## Features

- Securely store passwords
- Retrieve stored passwords
- Manage (add, update, delete) passwords
- Hash and validate passwords using bcrypt

## Installation

To get started with the project, you need to have [Rust](https://www.rust-lang.org/tools/install) installed. Then, you can clone the repository and build the project.

```
git clone https://github.com/yourusername/cli-password-manager.git
cd cli-password-manager
cargo build
```
## Dependencies 

This project uses the following crates:

```
[dependencies]
bcrypt = "0.15"
aes = "0.7.5"
block-modes = "0.8.1"
sha2 = "0.10.0"
hex = "0.4.3"
openssl = "0.10.38"
rand = "0.8.4"
```

To get started with the project, you need to have [Rust](https://www.rust-lang.org/tools/install) and OpenSSL installed. If you don't have OpenSSL installed, you can install it using your system's package manager or download it from the [OpenSSL website](https://www.openssl.org/).
