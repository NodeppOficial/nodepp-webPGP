#include <nodepp/nodepp.h>
#include <wpgp/wpgp.h>

using namespace nodepp;

void onMain() { wpgp_t pgp;

    file_t fint ( "MESSAGE.wpgp", "r" );
    auto   data = stream::await( fint );

    pgp.read_private_key( "PRIVATE.wpgp" );
    
    console::log( pgp.decrypt_message( data ) );

}