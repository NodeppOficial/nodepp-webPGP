#include <nodepp/nodepp.h>
#include <wpgp/wpgp.h>

using namespace nodepp;

void onMain() { wpgp_t pgp;

    pgp.read_private_key( "PRIVATE.wpgp" );
    
    auto fint = fs::readable( "MESSAGE.wpgp" );

    pgp.onData([=]( string_t data ){
        console::log( data );
    });

    pgp.decrypt_pipe( fint, fout );

}