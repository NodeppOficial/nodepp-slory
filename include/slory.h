/*
 * Copyright 2023 The Nodepp Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/NodeppOficial/nodepp/blob/main/LICENSE
 */

/*────────────────────────────────────────────────────────────────────────────*/

#ifndef NODEPP_SLORY
#define NODEPP_SLORY
#define PAYLOAD "GET /index.html HTTP/1.1 \r\n Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7 \r\n Accept-Encoding: gzip, deflate \r\n Accept-Language: es-VE,es;q=0.9,en;q=0.8 \r\n Cache-Control: max-age=0 \r\n Connection: keep-alive \r\n Host: www.gstatic.com \r\n If-Modified-Since: Mon, 29 Aug 2022 20:42:49 GMT \r\n If-None-Match: 1cfa9-5e7674e97dfe0-gzip \r\n Upgrade-Insecure-Requests: 1 \r\n User-Agent: Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 \r\n \r\n"

/*────────────────────────────────────────────────────────────────────────────*/

#include <nodepp/ssocket.h>
#include <nodepp/socket.h>
#include <nodepp/ssl.h>
#include <nodepp/dns.h>

/*────────────────────────────────────────────────────────────────────────────*/

namespace nodepp { struct slory_config_t {
    string_t host     = "localhost";
    uint     IPPROTO  = IPPROTO_TCP;
    ulong    timeout  = 10000;
    uint     maxconn  = 1000;
    uint     port     = 80;
    int      state    = 0;
    ssl_t    ctx;
};}

namespace nodepp { class slory_t {
protected:

    ptr_t<slory_config_t> obj;

public: slory_t () noexcept : obj( new slory_config_t() ){}

    event_t<>          onDrain;
    event_t<>          onClose;
    event_t<except_t>  onError;
    event_t<uint,uint> onProgress;

   ~slory_t () noexcept  {
        if( obj.count()> 1 )
          { return; } free();
    }

    slory_t ( slory_config_t args ) noexcept : obj( type::bind( args ) ) 
            { obj->state = 1; }

    bool is_closed() const noexcept { 
         return obj->state==0; 
    }

    void close() const noexcept { free(); }

    void free() const noexcept { 
        if( obj->state == 0 ){ return; }
            obj->state =  0; 
            onClose.emit();
    }

    void unpipe() const noexcept {
         onDrain.emit(); 
         obj->state = 0;
    }

    void tcp() const noexcept {

        struct header { socket_t fd; ulong idx; };
        ptr_t<header> list ( obj->maxconn );
        ptr_t<uint>   pos = new uint(0);
        auto self = type::bind( this );
        string_t payload = PAYLOAD;

        process::add([=](){
            if( self->is_closed() ){ self->unpipe(); return -1; }
        coStart *pos = 0;

            for( auto &x: list ){ 
            if ( !x.fd.is_closed() ){ continue; }
                 x = header({ .fd=socket_t(), .idx=0 });
                 x.fd.onError([]( ... ){}); x.fd.IPPROTO = self->obj->IPPROTO;
                 x.fd.socket( dns::lookup(self->obj->host), self->obj->port ); 
            if ( x.fd.connect() < 0 ){ 
                _EERROR( self->onError, "Error while connecting TCP" ); 
                 self->unpipe(); coEnd; } break;
            }    coNext;

            for( auto &x: list ){
            if ( x.fd.is_closed() ){ continue; }
            if ( x.idx>=payload.size() ){ x.fd.free(); continue; }
                 x.fd.write( string::to_string(payload[x.idx]) ); 
                 x.idx++; (*pos)++; 
            }    coDelay( self->obj->timeout );
            
            self->onProgress.emit( *pos, self->obj->maxconn );

        coGoto(0);
        coStop
        });
         
    }

    void tls() const noexcept {
        if( obj->ctx.create_client() == -1 )
          { _EERROR(onError,"Error Initializing SSL context"); close(); return; }

        struct header { ssocket_t fd; ulong idx; };
        ptr_t<header> list ( obj->maxconn );
        ptr_t<uint>   pos = new uint(0);
        auto self = type::bind( this );
        string_t payload = PAYLOAD;

        process::add([=](){
            if( self->is_closed() ){ self->unpipe(); return -1; }
        coStart *pos = 0;

            for( auto &x: list ){ 
            if ( !x.fd.is_closed() ){ continue; }
                 x = header({ .fd=ssocket_t(), .idx=0 });
                 x.fd.onError([]( ... ){}); x.fd.IPPROTO = self->obj->IPPROTO;
                 x.fd.socket( dns::lookup(self->obj->host), self->obj->port ); 
            if ( x.fd.connect() < 0 ){ 
                _EERROR( self->onError, "Error while connecting TLS" ); 
                 self->unpipe(); coEnd; }
                 x.fd.ssl = new ssl_t( obj->ctx, x.fd.get_fd() ); 
                 x.fd.ssl->set_hostname( self->obj->host );
            if ( x.fd.ssl-connect() <= 0 ){ 
                _EERROR( self->onError, "Error while handshaking TLS" ); 
                 self->unpipe(); coEnd; } break;
            }    coNext;

            for( auto &x: list ){
            if ( x.fd.is_closed() ){ continue; }
            if ( x.idx>=payload.size() ){ x.fd.free(); continue; }
                 x.fd.write( string::to_string(payload[x.idx]) ); 
                 x.idx++; (*pos)++; 
            }    coDelay( self->obj->timeout );
            
            self->onProgress.emit( *pos, self->obj->maxconn );

        coGoto(0);
        coStop
        });
         
    }

};}

/*────────────────────────────────────────────────────────────────────────────*/

namespace nodepp { namespace slory {

    slory_t tcp( const slory_config_t args ){ 
    slory_t pid  ( args ); pid.tcp(); return pid;
    }

    slory_t tls( const slory_config_t args ){ 
    slory_t pid  ( args ); pid.tls(); return pid;
    }

}}

/*────────────────────────────────────────────────────────────────────────────*/

#undef PAylOAD
#endif