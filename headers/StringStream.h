#pragma once

#include "IStream.h"
#include "helpers.h"

class StringStream;
typedef std::shared_ptr<StringStream> StringStreamPtr;

class StringStream: public IStream
{
public:
    virtual ~StringStream(){};

    int writeBuf(const unsigned char* buf, unsigned int size);

    int readBuf(unsigned char* buf, unsigned int size);

    unsigned int getSize();

    void addString(const std::string& add);

    std::string getString();

private:
    std::stringstream ss;
};
