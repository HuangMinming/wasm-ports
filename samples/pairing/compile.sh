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


# em++ -O2 -c c_pre.c sha256.c -s WASM=1 -I $EMSCRIPTEN/system/include -std=c++11
# em++ c_pre.o sha256.o -s WASM=1 -lff -lpbc -lgmp -I $EMSCRIPTEN/system/include -std=c++11 -o c_pre.js -s EXPORTED_FUNCTIONS='["_Enc1Test", "_Enc2Test", "_ReEncTest"]' -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap"]' -s MODULARIZE=1 -s EXIT_RUNTIME=1 -s NO_EXIT_RUNTIME=0
# em++ c_pre.o sha256.o -s WASM=1 -lff -lpbc -lgmp -I $EMSCRIPTEN/system/include -std=c++11 -o c_pre.js

emcc -O2 -c c_pre.c sha256.c -s WASM=1 -I $EMSCRIPTEN/system/include
emcc c_pre.o sha256.o -s WASM=1 -lff -lpbc -lgmp -I $EMSCRIPTEN/system/include -o c_pre.js -s EXPORTED_FUNCTIONS='["_Enc1Test", "_Enc2Test", "_ReEncTest", "_main_test", "_keyGenTest", "_malloc", "_free"]' -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap", "UTF8ToString", "allocate", "allocateUTF8"]' -s MODULARIZE=1 -s EXIT_RUNTIME=1 -s NO_EXIT_RUNTIME=0
emcc c_pre.o sha256.o -s WASM=1 -lff -lpbc -lgmp -I $EMSCRIPTEN/system/include -o c_pre.js -s EXIT_RUNTIME=1 -s NO_EXIT_RUNTIME=0
#生成js和wasm
emcc -O2 -c c_pre.c sha256.c -s WASM=1 -I $EMSCRIPTEN/system/include
emcc c_pre.o sha256.o -s WASM=1 -lpbc -lgmp -I $EMSCRIPTEN/system/include -o c_pre.js -s NO_EXIT_RUNTIME=0
emcc c_pre.o sha256.o -s WASM=1 -lpbc -lgmp -I $EMSCRIPTEN/system/include -o c_pre.js -s EXPORTED_FUNCTIONS='["_main", "_Enc1Test", "_Enc2Test", "_ReEncTest", "_KeyGen", "_Enc2", "_Dec2", "_ReKeyGen", "_ReEnc", "_Enc1", "_Dec1", "_malloc", "_free"]' -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap", "UTF8ToString", "allocate", "allocateUTF8"]' -s MODULARIZE=1 -s NO_EXIT_RUNTIME=0

#以下为最终使用命令，仅生成js文件
#运行第一条后，再运行第二条命令，然后可以用node c_pre.js来验证命令，最后用第三条命令导出
emcc -O3 -c c_pre.c sha256.c -I $EMSCRIPTEN/system/include
emcc c_pre.o sha256.o -lpbc -lgmp -I $EMSCRIPTEN/system/include -o c_pre.js -s NO_EXIT_RUNTIME=0
emcc c_pre.o sha256.o -lpbc -lgmp -I $EMSCRIPTEN/system/include -o c_pre.js -s EXPORTED_FUNCTIONS='["_main", "_Enc1Test", "_Enc2Test", "_ReEncTest", "_KeyGen", "_Enc2", "_Dec2", "_ReKeyGen", "_ReEnc", "_Enc1", "_Dec1", "_malloc", "_free"]' -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap", "UTF8ToString", "allocate", "allocateUTF8"]' -s MODULARIZE=1 -s NO_EXIT_RUNTIME=0 -s "SINGLE_FILE=1"
