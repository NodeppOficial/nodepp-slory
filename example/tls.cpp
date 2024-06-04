#include <nodepp/nodepp.h>
#include <nodepp/ssl.h>
#include <slory.h>

using namespace nodepp;

void onMain(){

    ssl_t ssl ( "ssl/cert.key", "ssl/cert.crt" );

    slory_config_t args;
    args.host     = "localhost";
    args.IPPROTO  = IPPROTO_TCP;
    args.timeout  = 10000;
    args.maxconn  = 1000;
    args.port     = 8000;
    args.ctx      = ssl;

    auto slory = slory::tls( args );
    console::log("slowlory started");

    slory.onProgress([=]( uint a, uint b ){
        console::log( "->", a, b );
    });

}