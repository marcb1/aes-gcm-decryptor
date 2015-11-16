RM = rm -fv

CPPFLAGS += -ggdb -Wall -std=c++0x -I. -Isrc -Iheaders
LIB_FLAGS=-lcrypto -lssl

all: encrypt_main encrypt_lib test_main

SRC_ENCRYPT= src/aesEncryptor.cpp src/StringStream.cpp
OBJ_ENCRYPT= $(SRC_ENCRYPT:.cpp=.o)

encrypt_main: $(OBJ_ENCRYPT) src/encryptorMain.cpp
	g++ $(CPPFLAGS) $(OBJ_ENCRYPT) src/encryptorMain.cpp $(LIB_FLAGS) -o encrypt_main

test_main: $(OBJ_ENCRYPT) src/testMain.cpp
	g++ $(CPPFLAGS) $(OBJ_ENCRYPT) src/testMain.cpp $(LIB_FLAGS) -o test_main

encrypt_lib: $(OBJ_ENCRYPT)
	ar rcs libencryptor.a $(OBJ_ENCRYPT)

clean:
	-$(RM) *.o encrypt_main client_main server_main
