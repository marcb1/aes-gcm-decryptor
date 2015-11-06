RM = rm -fv


CPPFLAGS += -ggdb -Wall -std=c++0x -I.
LIB_FLAGS=-lcrypto -lssl

all: encrypt_main encrypt_lib

SRC_ENCRYPT= encryptorMain.cpp aesEncryptor.cpp
OBJ_ENCRYPT= $(SRC_ENCRYPT:.cpp=.o)

encrypt_lib: $(OBJ_ENCRYPT)
	ar rcs libencryptor.a $(OBJ_ENCRYPT)

encrypt_main: $(OBJ_ENCRYPT)
	g++ $(CPPFLAGS) aesEncryptor.cpp encryptorMain.cpp $(LIB_FLAGS) -o encrypt_main

clean:
	-$(RM) *.o encrypt_main client_main server_main
