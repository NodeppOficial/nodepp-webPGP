#include <nodepp/nodepp.h>
#include <nodepp/ws.h>
#include <wpgp/wpgp.h>

using namespace nodepp;

void server() {

    ptr_t<queue_t<ws_t>> list = new queue_t<ws_t>();
    auto server = ws::server();

    server.onConnect([=]( ws_t cli ){
        list->push(cli); auto ID=list->last();

        cli.onData([=]( string_t data ){
            auto x = list->first(); while( x!=nullptr ){ 
                if( x==ID ){ x=x->next; continue; }
                x->data.write(data); x = x->next;
            }   console::log( data );
        });

        cli.onClose([=](){ list->erase(ID); 
            console::log("disconnected");
        }); console::log("connected");

    });

    wpgp_t pgp;
    pgp.create_new_user( 
        "EDBC",          // Name
        "EDBC@mail.com", // Mail (Optional)
        "Hello World 1", // Comment
        3,               // Expiration (DAYS)
        2048             // RSA size
    );

    pgp.write_private_key( "PRIVATE.wpgp" );

    server.listen( "localhost", 8000, [=](...){
        console::log("-> ws://localhost:8000");
    });

}

void client() {

    auto client = ws::client( "ws://localhost:8000" );
    auto cin    = fs::std_input(); wpgp_t pgp;
    pgp.read_private_key( "PRIVATE.wpgp" );

    client.onConnect([=]( ws_t cli ){
        
        cli.onClose([](){
            console::log("diconnected");
            process::exit(1);
        }); console::log("connected");

        cin.onData([=]( string_t data ){ cli.write( pgp.encrypt_message(data) ); });
        cli.onData([=]( string_t data ){ console::log( pgp.decrypt_message(data) ); });

    });

    stream::pipe( cin );

}

void onMain() {
    if( process::env::get("mode")=="server" )
      { server(); } else { client(); }
}
