#include <nodepp/nodepp.h>
#include <wpgp/wpgp.h>

using namespace nodepp;

void onMain() { wpgp_t pgp;

    pgp.read_private_key( "PUBLIC.wpgp" );
    
    auto fint = fs::readable( "LICENSE" );
    auto fout = fs::writable( "MESSAGE.wpgp" );
    
    pgp.encrypt_pipe( fint, fout );

}