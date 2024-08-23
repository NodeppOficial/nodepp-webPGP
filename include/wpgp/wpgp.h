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
#include <nodepp/zlib.h>
#include <nodepp/fs.h>

/*────────────────────────────────────────────────────────────────────────────*/
    
namespace nodepp { class wpgp_t {
protected:

    struct NODE {

        ulong    size; // RSA size
        bool     prvt; // Private Key Bool
        string_t name; // User Name
        string_t mail; // User Mail
        string_t cmmt; // User Comment
        uint  stmp[2]; // Expiration Stamp
        rsa_t fd;      // RSA File Descriptor

    };  ptr_t<NODE> obj;

public: wpgp_t() noexcept : obj( new NODE() ) {}

    /*─······································································─*/

    event_t<except_t> onError;
    event_t<>         onClose;
    event_t<string_t> onData;

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

    void write_private_key( const string_t& path, const string_t& pass ) const {
        auto file = fs::writable( path ); file.write( write_private_key_to_memory( pass ) );
    }

    string_t write_private_key_to_memory( const string_t& pass ) const noexcept {
        string_t data = "WPGP.PRIVATE."; auto sha = crypto::hash::SHA256();
        auto     body = obj->fd.write_private_key_to_memory( pass.get() );

        auto header = json::stringify( object_t({
            { "name", obj->name }, { "mail", obj->mail }, { "comment", obj->cmmt },
            { "expiration", array_t<uint>({ obj->stmp[0], obj->stmp[1] }) },
            { "size", obj->size }
        }) );

        data += encoder::base64::get( header ) + ".";
        data += encoder::base64::get( body )   + ".";

        sha.update( data );
        data += encoder::base64::get( sha.get() );

        return data;
    }

    /*─······································································─*/

    void write_public_key( const string_t& path ) const {
        auto file = fs::writable( path ); file.write( write_public_key_to_memory() );
    }

    string_t write_public_key_to_memory() const noexcept { 
        string_t data = "WPGP.PUBLIC.";  auto sha = crypto::hash::SHA256();
        auto     body = obj->fd.write_public_key_to_memory();

        auto header = json::stringify( object_t({
            { "name", obj->name }, { "mail", obj->mail }, { "comment", obj->cmmt },
            { "expiration", array_t<uint>({ obj->stmp[0], obj->stmp[1] }) },
            { "size", obj->size }
        }) );

        data += encoder::base64::get( header ) + ".";
        data += encoder::base64::get( body )   + ".";

        sha.update( data );
        data += encoder::base64::get( sha.get() );

        return data;
    }

    /*─······································································─*/

    void read_private_key_from_memory( const string_t& pkey, const string_t& pass ) const {
        if( !verify_key_from_memory( pkey ) ){ _EERROR( onError, "Invalid WPGP Key" ); return; }

        auto data = regex::match_all( pkey, "[^.]+" );
        if( data[1] != "PRIVATE" ){ _EERROR( onError, "Invalid WPGP Key" ); return; }

        auto header = json::parse( encoder::base64::set( data[2] ) );
        auto body   = encoder::base64::set( data[3] );

        obj->prvt    = true;
        obj->size    = header["size"].as<uint>();
        obj->name    = header["name"].as<string_t>();
        obj->mail    = header["mail"].as<string_t>();
        obj->cmmt    = header["comment"].as<string_t>();
        obj->stmp[0] = header["expiration"][0].as<int>();
        obj->stmp[1] = header["expiration"][1].as<int>();

        obj->fd.read_private_key_from_memory( body, pass.get() );
    }

    void read_private_key( const string_t& path, const string_t& pass ) const {
        file_t file ( path, "r" ); 
        auto data = stream::await( file );
        read_private_key_from_memory( data, pass );
    }

    /*─······································································─*/

    void read_public_key_from_memory( const string_t& pkey ) const {
        if( !verify_key_from_memory( pkey ) ){ _EERROR( onError, "Invalid WPGP Key" ); return; }
        auto data = regex::match_all( pkey, "[^.]+" );
        if( data[1] != "PUBLIC" ){ _EERROR( onError, "Invalid WPGP Key" ); return; }

        auto header = json::parse( encoder::base64::set( data[2] ) );
        auto body   = encoder::base64::set( data[3] );

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
        string_t data = "WPGP.MESSAGE."; 
        auto     sec  = crypto::hash::SHA256();

        sec.update( string::to_string( rand() ) );
        sec.update( string::to_string( process::now() ) );
        sec.update( obj->fd.write_private_key_to_memory() );

        auto enc = crypto::encrypt::AES_256_ECB( sec.get() );
             enc.update( message );

        data += encoder::base64::get( obj->fd.public_encrypt( sec.get() ) );
        data += "." + enc.get(); return data;
    }

    template< class T >
    void encrypt_pipe( const T& fileA ) const noexcept {
        auto sec = crypto::hash::SHA256();

        sec.update( string::to_string( rand() ) );
        sec.update( string::to_string( process::now() ) );
        sec.update( obj->fd.write_private_key_to_memory() );

        auto enc = crypto::encrypt::AES_256_ECB( sec.get() );
        auto self= type::bind( this );

        onData.emit( "WPGP.MESSAGE." + encoder::base64::get( obj->fd.public_encrypt( sec.get() ) ) + "." );
        enc.onData([=]( string_t data ){ self->onData.emit( data ); });
        fileA.onData([=]( string_t data ){ enc.update( data ); });

        stream::pipe( fileA );
    }

    template< class T, class V >
    void encrypt_pipe( const T& fileA, const V& fileB ) const noexcept {
        onData([=]( string_t data ){ fileB.write( data ); });
        encrypt_pipe( fileA );
    }

    /*─······································································─*/

    string_t decrypt_message( const string_t& message ) const noexcept {
        auto data = regex::match_all( message, "[^.]+" );
        if( data[0] != "WPGP" || data[1] != "MESSAGE" ){ return nullptr; }

        auto pass = obj->fd.private_decrypt( encoder::base64::set( data[2] ) );
        auto pos  = regex::search_all( message, "[.]+" );
        auto dec  = crypto::decrypt::AES_256_ECB( pass );

        dec.update( message.slice( pos[2][1] ) ); return dec.get();
    }

    template< class T >
    void decrypt_pipe( const T& fileA ) const noexcept {

        if( fileA.read_until('.').slice(0,-1) != "WPGP" )   { _EERROR( onError, "Invalid WPGP Format" ); return; }
        if( fileA.read_until('.').slice(0,-1) != "MESSAGE" ){ _EERROR( onError, "Invalid WPGP Format" ); return; }

        auto pass = encoder::base64::set( fileA.read_until('.').slice(0,-1) );
             pass = obj->fd.private_decrypt( pass );
        auto dec  = crypto::decrypt::AES_256_ECB( pass );

        auto self = type::bind( this );

        dec.onData([=]( string_t data ){ self->onData.emit( data ); });
        fileA.onData([=]( string_t data ){ dec.update( data ); });

        stream::pipe( fileA );
    }

    template< class T, class V >
    void decrypt_pipe( const T& fileA, const V& fileB ) const noexcept {
        onData([=]( string_t data ){ fileB.write( data ); });
        decrypt_pipe( fileA );
    }

    /*─······································································─*/

    bool verify_message( const string_t& message ) const noexcept {
        return nullptr;
    }

    string_t sign_message( const string_t& message ) const noexcept {
        return nullptr;
    }

    template< class T >
    bool verify_pipe( const T& file ) const noexcept {
        return false;
    }

    template< class T >
    void sign_pipe( const T& file ) const noexcept {}

    template< class T, class V >
    void sign_pipe( const T& fileA, const V& fileB ) const noexcept {}

    /*─······································································─*/

    bool verify_key_from_memory( const string_t& pkey ) const noexcept {
        try {
            auto data = regex::match_all( pkey, "[^.]+" );
            auto hash = crypto::hash::SHA256();

            hash.update( regex::format( "${0}.${1}.${2}.${3}.", 
                data[0], data[1], data[2], data[3]
            ));

            auto exp  = json::parse( encoder::base64::set(data[2]) )["expiration"];
            auto ssum = encoder::base64::get( hash.get() );

            if( exp[0].as<uint>() != 0 ){
            if( exp[0].as<uint>()+exp[1].as<uint>() < process::seconds()/86400 ){ return false; }
            }

            if( data.empty() || data.size() != 5 )                              { return false; }
            if( data[0] != "WPGP" )                                             { return false; }
            if( data[4] != ssum )                                               { return false; }

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

};}

/*────────────────────────────────────────────────────────────────────────────*/

#endif

/*────────────────────────────────────────────────────────────────────────────*/