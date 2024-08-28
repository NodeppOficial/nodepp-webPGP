/*
 * Copyright 2023 The Nodepp Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/NodeppOficial/nodepp/blob/main/LICENSE
 */

/*────────────────────────────────────────────────────────────────────────────*/

#ifndef NODEPP_WPGP
#define NODEPP_WPGP

/*────────────────────────────────────────────────────────────────────────────*/

#include <nodepp/nodepp.h>

#include <nodepp/encoder.h>
#include <nodepp/crypto.h>
#include <nodepp/event.h>
#include <nodepp/json.h>
#include <nodepp/fs.h>

/*────────────────────────────────────────────────────────────────────────────*/
    
namespace nodepp { class wpgp_t {
protected:

    struct CTX {
        char  format[5] = {"WPGP"};
        ulong header[2] = {0,0};
        ulong   body[2] = {0,0};
        ulong   hash[2] = {0,0};
        char    mask[5] ;
    };

    struct NODE {
        bool  state=0;

        ulong    size; // RSA size
        bool     prvt; // Private Key Bool
        string_t name; // User Name
        string_t mail; // User Mail
        string_t cmmt; // User Comment
        uint  stmp[2]; // Expiration Stamp
        rsa_t fd;      // RSA File Descriptor

    };  ptr_t<NODE> obj;

public: 

    event_t<except_t> onError;
    event_t<>         onClose;
    event_t<string_t> onData;

    /*─······································································─*/

     wpgp_t() noexcept : obj( new NODE() ) {}
    ~wpgp_t() noexcept { if( obj.count() > 1 ){ return; } free(); };

    /*─······································································─*/

    void create_new_user( string_t _name, string_t _mail, string_t _cmmt, uint max_age=0, uint size=1024 ) const noexcept {
        if( max_age == 0 ) { obj->stmp[0] = 0; obj->stmp[1] = 0; } else { 
            obj->stmp[0] = process::seconds() / 86400;
            obj->stmp[1] = min( max_age, 365u );
        }   obj->fd = crypto::encrypt::RSA(); obj->fd.generate_keys( size ); 
        obj->size = size; obj->name = _name; obj->mail = _mail; obj->cmmt = _cmmt; obj->prvt = true;
    }

    /*─······································································─*/

    string_t get_name()    const noexcept { return obj->name; }
    string_t get_mail()    const noexcept { return obj->mail; }
    string_t get_comment() const noexcept { return obj->cmmt; }
    uint* get_expiration() const noexcept { return obj->stmp; }
    ulong get_size()       const noexcept { return obj->size; }

    /*─······································································─*/

    void write_private_key( const string_t& path, const string_t& pass=nullptr ) const {
        auto file = fs::writable( path ); file.write( write_private_key_to_memory( pass ) );
    }

    string_t write_private_key_to_memory( const string_t& pass=nullptr ) const noexcept {
        CTX ctx; memcpy( &ctx.mask, encoder::key::generate( 4 ).get(), 5 );
        
        auto body   = obj->fd.write_private_key_to_memory( pass.get() );
             body   = encoder::base64::get( encoder::XOR::get( body, ctx.mask ) );

        auto sha    = crypto::hash::SHA256(); 

        auto header = encoder::base64::get( encoder::XOR::get( 
            json::stringify( object_t({
                { "name", obj->name }, { "mail", obj->mail }, { "comment", obj->cmmt },
                { "expiration", array_t<uint>({ obj->stmp[0], obj->stmp[1] }) },
                { "size", obj->size }, { "type", "PRIVATE" }
            }) 
        ), ctx.mask ));

        sha.update( body ); sha.update( header );

        ctx.body[0]   = 0;
        ctx.body[1]   = ctx.body[0]   + body.size();

        ctx.header[0] = ctx.body[1]   ;
        ctx.header[1] = ctx.header[0] + header.size();

        ctx.hash[0]   = ctx.header[1] ;
        ctx.hash[1]   = ctx.hash[0]   + sha.get().size();

        return body + header + sha.get() + string_t( (char*)& ctx, sizeof( CTX ) );
    }

    /*─······································································─*/

    void write_public_key( const string_t& path ) const {
        auto file = fs::writable( path ); file.write( write_public_key_to_memory() );
    }

    string_t write_public_key_to_memory() const noexcept { 
        CTX ctx; memcpy( &ctx.mask, encoder::key::generate( 4 ).get(), 5 );
        
        auto body   = obj->fd.write_public_key_to_memory();
             body   = encoder::base64::get( encoder::XOR::get( body, ctx.mask ) );

        auto sha    = crypto::hash::SHA256(); 

        auto header = encoder::base64::get( encoder::XOR::get( 
            json::stringify( object_t({
                { "name", obj->name }, { "mail", obj->mail }, { "comment", obj->cmmt },
                { "expiration", array_t<uint>({ obj->stmp[0], obj->stmp[1] }) },
                { "size", obj->size }, { "type", "PUBLIC" }
            }) 
        ), ctx.mask ));

        sha.update( body ); sha.update( header );

        ctx.body[0]   = 0;
        ctx.body[1]   = ctx.body[0]   + body.size();

        ctx.header[0] = ctx.body[1]   ;
        ctx.header[1] = ctx.header[0] + header.size();

        ctx.hash[0]   = ctx.header[1] ;
        ctx.hash[1]   = ctx.hash[0]   + sha.get().size();

        return body + header + sha.get() + string_t( (char*)& ctx, sizeof( CTX ) );
    }

    /*─······································································─*/

    void read_private_key_from_memory( const string_t& pkey, const string_t& pass=nullptr ) const {
        if( !verify_key_from_memory( pkey ) ){ _EERROR( onError, "Invalid WPGP Key" ); return; }
        CTX ctx; memcpy( &ctx, pkey.slice( -sizeof( CTX ) ).get(), sizeof( CTX ) );
        
        auto header = json::parse( encoder::XOR::get( encoder::base64::set( 
             pkey.slice( ctx.header[0], ctx.header[1] )
        ), ctx.mask ));

        auto body = encoder::XOR::get( encoder::base64::set( 
             pkey.slice( ctx.body[0], ctx.body[1] ) 
        ), ctx.mask );

        if( header["type"].as<string_t>() != "PRIVATE" )
          { _EERROR( onError, "Invalid WPGP Key" ); return; }

        obj->prvt    = true;
        obj->size    = header["size"].as<uint>();
        obj->name    = header["name"].as<string_t>();
        obj->mail    = header["mail"].as<string_t>();
        obj->cmmt    = header["comment"].as<string_t>();
        obj->stmp[0] = header["expiration"][0].as<int>();
        obj->stmp[1] = header["expiration"][1].as<int>();

        obj->fd.read_private_key_from_memory( body, pass.get() );
    }

    void read_private_key( const string_t& path, const string_t& pass=nullptr ) const {
        file_t file ( path, "r" ); 
        auto data = stream::await( file );
        read_private_key_from_memory( data, pass );
    }

    /*─······································································─*/

    void read_public_key_from_memory( const string_t& pkey ) const {
        if( !verify_key_from_memory( pkey ) ){ _EERROR( onError, "Invalid WPGP Key" ); return; }
        CTX ctx; memcpy( &ctx, pkey.slice( -sizeof( CTX ) ).get(), sizeof( CTX ) );
        
        auto header = json::parse( encoder::XOR::get( encoder::base64::set( 
             pkey.slice( ctx.header[0], ctx.header[1] )
        ), ctx.mask ));

        auto body = encoder::XOR::get( encoder::base64::set( 
             pkey.slice( ctx.body[0], ctx.body[1] ) 
        ), ctx.mask );

        if( header["type"].as<string_t>() != "PUBLIC" )
          { _EERROR( onError, "Invalid WPGP Key" ); return; }

        obj->prvt    = false;
        obj->size    = header["size"].as<uint>();
        obj->name    = header["name"].as<string_t>();
        obj->mail    = header["mail"].as<string_t>();
        obj->cmmt    = header["comment"].as<string_t>();
        obj->stmp[0] = header["expiration"][0].as<int>();
        obj->stmp[1] = header["expiration"][1].as<int>();

        obj->fd.read_public_key_from_memory( body );
    }

    void read_public_key( const string_t& path ) const {
        file_t file ( path, "r" ); 
        auto data = stream::await( file );
        read_public_key_from_memory( data );
    }

    /*─······································································─*/

    string_t encrypt_message( const string_t& message ) const noexcept { 
        CTX ctx; auto sec = crypto::hash::SHA256();
                 auto sha = crypto::hash::SHA256();

        memcpy( &ctx.mask, encoder::key::generate( 4 ).get(), 5 );

        sec.update( string::to_string( rand() ) );
        sec.update( string::to_string( process::now() ) );
        sec.update( obj->fd.write_private_key_to_memory() );

        auto enc = crypto::encrypt::AES_256_ECB( sec.get() );
                   enc.update( message );
        
        auto body   = encoder::base64::get( encoder::XOR::get( 
             enc.get(), ctx.mask
        ));

        auto header = encoder::base64::get( encoder::XOR::get(
             obj->fd.public_encrypt( json::stringify( object_t({
                { "size", message.size() }, { "type", "MESSAGE" }, 
                { "pass", sec.get()      }
             }))
        ), ctx.mask ));

        sha.update( body ); sha.update( header );

        ctx.body[0]   = 0;
        ctx.body[1]   = ctx.body[0]   + body.size();

        ctx.header[0] = ctx.body[1]   ;
        ctx.header[1] = ctx.header[0] + header.size();

        ctx.hash[0]   = ctx.header[1] ;
        ctx.hash[1]   = ctx.hash[0]   + sha.get().size();

        return body + header + sha.get() + string_t( (char*)& ctx, sizeof( CTX ) );
    }

    template< class T >
    void encrypt_pipe( const T& fileA ) const noexcept {
        char pass[5]; memcpy( pass, encoder::key::generate(4).get(), 5 );

        auto XOR = crypto::encrypt::XOR( pass );
        auto b64 = crypto::encoder::BASE64();
        auto sec = crypto::hash::SHA256();
        auto sha = crypto::hash::SHA256();
        auto self= type::bind( this );

        ptr_t<ulong> length = new ulong(0);

        sec.update( string::to_string( rand() ) );
        sec.update( string::to_string( process::now() ) );
        sec.update( obj->fd.write_private_key_to_memory() );

        auto enc = crypto::encrypt::AES_256_ECB( sec.get() );

        fileA.onData([=]( string_t data ){ enc.update( data ); });
        enc  .onData([=]( string_t data ){ XOR.update( data ); });
        XOR  .onData([=]( string_t data ){ b64.update( data ); });
        b64  .onData([=]( string_t data ){
            self->onData.emit( data ); 
           *length += data.size();
            sha.update( data );
        });

        fileA.onClose([=](){ enc.free(); b64.free(); 
            CTX ctx; memcpy( ctx.mask, pass, 5 );

            auto header = encoder::base64::get( encoder::XOR::get(
                 self->obj->fd.public_encrypt( json::stringify( object_t({
                    { "size", *length   }, { "type", "MESSAGE" },
                    { "pass", sec.get() },
                 }))
            ), ctx.mask )); sha.update( header );

            ctx.body[0]   = 0;
            ctx.body[1]   = ctx.body[0]   + *length;

            ctx.header[0] = ctx.body[1]   ;
            ctx.header[1] = ctx.header[0] + header.size();

            ctx.hash[0]   = ctx.header[1] ;
            ctx.hash[1]   = ctx.hash[0]   + sha.get().size();

            self->onData.emit( header ); self->onData.emit( sha.get() );
            self->onData.emit( string_t( (char*) &ctx, sizeof(CTX) ) );
            self->onClose.emit();

        });

        stream::pipe( fileA );
    }

    template< class T, class V >
    void encrypt_pipe( const T& fileA, const V& fileB ) const noexcept {
        onData([=]( string_t data ){ fileB.write( data ); });
        encrypt_pipe( fileA );
    }

    /*─······································································─*/

    string_t decrypt_message( const string_t& message ) const noexcept {
      //if( !verify_message_from_memory( message ) ){ _EERROR( onError, "Invalid WPGP Message" ); return; }

        if( message.empty() ){ return nullptr; }
        auto xtc = message.slice( -sizeof( CTX ) );

        CTX ctx; memcpy( &ctx, xtc.get(), sizeof( CTX ) );

        auto hash = crypto::hash::SHA256(); hash.update(
            message.slice( ctx.body[0], ctx.header[1] )
        );

        auto header = json::parse( obj->fd.private_decrypt( 
            encoder::XOR::get( encoder::base64::set(
                message.slice( ctx.header[0], ctx.header[1] )
            ), ctx.mask )
        ));

        auto sha = message.slice( ctx.hash[0], ctx.hash[1] );
        auto sec = header["pass"].as<string_t>();
        if ( sha != hash.get() ){ return nullptr; }

        auto dec = crypto::decrypt::AES_256_ECB( sec );
             dec.update( encoder::XOR::get( encoder::base64::set(
                message.slice( ctx.body[0], ctx.body[1] ) 
             ), ctx.mask ));

        return dec.get();
    }

    void decrypt_pipe( const file_t& fileA ) const noexcept {
      //if( !verify_message( fileA ) ){ _EERROR( onError, "Invalid WPGP Message" ); return; }

        fileA.pos( fileA.size() - sizeof( CTX ) );
        auto xtc = fileA.read( sizeof( CTX ) );
                   fileA.del_borrow();

        CTX ctx; memcpy( &ctx, xtc.get(), sizeof( CTX ) );

        fileA.pos( ctx.header[0] );
        auto xhr = fileA.read( ctx.header[1]-ctx.header[0] );
        auto hdr = json::parse( obj->fd.private_decrypt( 
            encoder::XOR::get( encoder::base64::set( xhr ), ctx.mask )
        )); fileA.del_borrow();

        auto sec = hdr["pass"].as<string_t>();
        ptr_t<ulong> len = new ulong(0);

        fileA.pos( ctx.hash[0] );
        auto sha = fileA.read( ctx.hash[1]-ctx.hash[0] );
                   fileA.del_borrow();

        auto dec = crypto::decrypt::AES_256_ECB( sec );
        auto XOR = crypto::encrypt::XOR( ctx.mask );
        auto b64 = crypto::decoder::BASE64();
        auto hash= crypto::hash::SHA256();
        auto self= type::bind( this );
             hash.update( xhr );

        fileA.onDrain([=](){ dec.free(); b64.free(); self->onClose.emit(); });
        dec.onData([=]( string_t data ){ self->onData.emit( data ); });
        b64.onData([=]( string_t data ){ XOR.update( data ); });
        XOR.onData([=]( string_t data ){ dec.update( data ); });
        fileA.pos( ctx.body[0] );

        process::add([=](){
            if( !fileA.is_available() ){ return -1; }
        coStart

            while( *len < ( ctx.body[1] - ctx.body[0] ) ){ do {
                auto dta = fileA.read( ( ctx.body[1] - ctx.body[0] ) - *len ); 
                     hash.update( dta ); b64.update( dta );
                    *len += dta.size();
            } while(0); coNext; }

            fileA.close();

        coStop
        });

    }

    template< class T, class V >
    void decrypt_pipe( const T& fileA, const V& fileB ) const noexcept {
        onData([=]( string_t data ){ fileB.write( data ); });
        decrypt_pipe( fileA );
    }

    /*─······································································─*/

    bool verify_key_from_memory( const string_t& pkey ) const noexcept {
        try { if( pkey.empty() ){ return false; }

            CTX ctx; memcpy( &ctx, pkey.slice( -sizeof( CTX ) ).get(), sizeof( CTX ) );
            auto hash = pkey.slice( ctx.hash[0], ctx.hash[1] ); 

            auto header = json::parse( encoder::XOR::get( encoder::base64::set( 
                pkey.slice( ctx.header[0], ctx.header[1] )
            ), ctx.mask ));

            auto exp  = header["expiration"];
            auto body = encoder::XOR::get( encoder::base64::set( 
                pkey.slice( ctx.body[0], ctx.body[1] ) 
            ), ctx.mask );

            auto sha  = crypto::hash::SHA256(); sha.update( 
                pkey.slice( ctx.body[0], ctx.header[1] )
            );

            if( memcmp( ctx.format, "WPGP", 5 ) < 0 ){ return false; }
            if( hash != sha.get() )                  { return false; }

            if( exp[0].as<uint>() != 0 )
            if( exp[0].as<uint>()+exp[1].as<uint>() < process::seconds()/86400 ){ return false; }

                        return true;
        } catch( ... ){ return false; }
    }

    bool verify_key( const string_t& path ) const noexcept {
        try { 
            file_t file ( path, "r" ); 
            auto data = stream::await( file );
            return verify_key_from_memory( data );
        } catch( ... ) { return false; }
    }

    /*─······································································─*/

    void free() const noexcept {
        if( obj->state == 0 ){ return; }
            obj->state =  0; onClose.emit();
    }

};}

/*────────────────────────────────────────────────────────────────────────────*/

#endif

/*────────────────────────────────────────────────────────────────────────────*/