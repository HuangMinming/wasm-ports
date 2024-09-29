#!/bin/sh

em++ -O2 -c pairing.cpp -s WASM=1 -I $EMSCRIPTEN/system/include -std=c++11
em++ pairing.o -s WASM=1 -lff -lpbc -lgmp -I $EMSCRIPTEN/system/include -std=c++11 -o pairing.js -s EXTRA_EXPORTED_RUNTIME_METHODS=['ccall','cwrap'] -s ENVIRONMENT='web,worker'
node ~/emscripten-module-wrapper/prepare.js pairing.js --debug --out dist --file _dev_urandom --file input.data --file output.data --upload-ipfs --analyze --run
cp dist/globals.wasm task.wasm
cp dist/info.json .
solc --overwrite --bin --abi --optimize contract.sol -o build

#manual call
#em++ -O2 -c pairing.cpp -s WASM=1 -I $EMSCRIPTEN/system/include -std=c++11
#em++ pairing.o -s WASM=1 -lff -lpbc -lgmp -I $EMSCRIPTEN/system/include -std=c++11 -o pairing.js -s EXPORTED_FUNCTIONS='["_myFunction", "_anotherFunction"]' -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap"]' -s MODULARIZE=1 -s EXIT_RUNTIME=1 -s NO_EXIT_RUNTIME=0


# em++ -O2 -c C-PRE.c sha256.c -s WASM=1 -I $EMSCRIPTEN/system/include -std=c++11
# em++ C-PRE.o sha256.o -s WASM=1 -lff -lpbc -lgmp -I $EMSCRIPTEN/system/include -std=c++11 -o C-PRE.js -s EXPORTED_FUNCTIONS='["_Enc1Test", "_Enc2Test", "_ReEncTest"]' -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap"]' -s MODULARIZE=1 -s EXIT_RUNTIME=1 -s NO_EXIT_RUNTIME=0
# em++ C-PRE.o sha256.o -s WASM=1 -lff -lpbc -lgmp -I $EMSCRIPTEN/system/include -std=c++11 -o C-PRE.js
