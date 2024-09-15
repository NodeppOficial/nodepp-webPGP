# WebPGP ( PGP Optimized for Web )

WPGP is an innovative approach to the traditional PGP (Pretty Good Privacy) encryption standard. While it is not a formal PGP standard, WPGP reimagines the original algorithm by leveraging modern web technologies. This allows for enhanced usability and accessibility, making secure communication more feasible for a broader audience.

By integrating contemporary advancements, WPGP aims to provide a user-friendly experience while maintaining the core principles of encryption and data protection that PGP is known for. This reimagining not only addresses the evolving needs of users but also ensures that security remains a top priority in the digital landscape.

## Dependencies
```bash
# Openssl
    🪟: pacman -S mingw-w64-ucrt-x86_64-openssl
    🐧: sudo apt install libssl-dev

# Nodepp
    💻: https://github.com/NodeppOficial/nodepp
```

## Build & Run
- 🪟: `g++ -o main main.cpp -I ./include -lz -lws2_32 -lssl -lcrypto ; ./main`
- 🐧: `g++ -o main main.cpp -I ./include -lz -lssl -lcrypto ; ./main`

## Usage

```cpp
#include <nodepp/nodepp.h>
#include <wpgp/wpgp.h>

using namespace nodepp;

void onMain() { wpgp_t pgp;

    pgp.create_new_user( 
        "EDBC",          // Name
        "EDBC@mail.com", // Mail
        "Hello World",   // Comment
        3,               // Expiration (DAYS)
        2048             // RSA size
    );

    pgp.write_private_key( "PRIVATE.wpgp" );
    console::log( pgp.write_private_key_to_memory() );

    pgp.write_public_key( "PUBLIC.wpgp" );
    console::log( pgp.write_public_key_to_memory() );

    auto enc = pgp.encrypt_message( "Hello World" );
    auto dec = pgp.decrypt_message( enc );

    console::log( enc );
    console::log( dec );

}
```

## License

**Nodepp** is distributed under the MIT License. See the LICENSE file for more details.
