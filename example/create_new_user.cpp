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

}