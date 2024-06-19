# argon2 - A Golang Package for Password Hashing with Argon2

## Overview

`argon2` is a Golang package that provides easy-to-use functions for hashing and verifying passwords using the Argon2id algorithm. Argon2 is a memory-hard password hashing algorithm designed to resist both GPU and side-channel attacks. This package ensures secure password storage and verification.

## Features

- Secure password hashing using Argon2id.
- Automatic salt generation for each password hash.
- Configurable parameters for memory, time, and parallelism.
- Constant time comparison for password verification to prevent timing attacks.

## Installation

To install the `argon2` package, use the following command:

```shellsession
$ go get github.com/bionicosmos/argon2
```

## Usage

### Hashing a Password

To hash a password, simply call the `Hash` function with the password string:

```go
package main

import (
	"fmt"

	"github.com/bionicosmos/argon2"
)

func main() {
	password := "B^G3cMzs0$14cH2201&&"
	hashedPassword := argon2.Hash(password)
	fmt.Println("Hashed Password:", hashedPassword)
    // Hashed Password: $argon2id$v=19$m=65536,t=1,p=8$EUfYfS8YbMh9bgBLTZE3Aw$l5XAX/80bljGYBvaHp3C1dt/x5pG5iG2clZahCun7hY
}
```

### Verifying a Password

To verify a password against a hashed password, use the `Verify` function:

```go
package main

import (
	"fmt"

	"github.com/bionicosmos/argon2"
)

func main() {
	password := "B^G3cMzs0$14cH2201&&"
	hashedPassword := "$argon2id$v=19$m=65536,t=1,p=8$EUfYfS8YbMh9bgBLTZE3Aw$l5XAX/80bljGYBvaHp3C1dt/x5pG5iG2clZahCun7hY"

	isValid := argon2.Verify(password, hashedPassword)
	fmt.Println("Password is valid:", isValid)
    // Password is valid: true
}
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

Feel free to contribute to the project by submitting issues or pull requests on the [GitHub repository](https://github.com/BioniCosmos/argon2).
