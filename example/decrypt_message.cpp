#include <nodepp/nodepp.h>
#include <wpgp/wpgp.h>

using namespace nodepp;

void onMain() { wpgp_t pgp;

    pgp.read_private_key( "PRIVATE.wpgp" );
    
    console::log( pgp.decrypt_message( "Hello World" ) );

}