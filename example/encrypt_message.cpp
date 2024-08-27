#include <nodepp/nodepp.h>
#include <wpgp/wpgp.h>

using namespace nodepp;

void onMain() { wpgp_t pgp;

    pgp.read_private_key( "PUBLIC.wpgp" );
    
    console::log( pgp.encrypt_message( "Hello World" ) );

}