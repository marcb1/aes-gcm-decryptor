#include "StringStream.h"

int StringStream::writeBuf(const unsigned char* buf, unsigned int size)
{
    std::string add(reinterpret_cast<const char*>(buf), size);
    ss << add;
    return size;
}

int StringStream::readBuf(unsigned char* buf, unsigned int size)
{
    std::string currentStream = ss.str();
    if(size == 0 || currentStream.size() == 0)
        return 0;
    if(size > currentStream.size())
    {
        size = currentStream.size();
    }
    strncpy((char*)buf, currentStream.c_str(), size);
    currentStream.erase(0, size);
    ss.str(currentStream);
    return size;
}

unsigned int StringStream::getSize()
{
    return ss.str().size();
}

void StringStream::addString(const std::string& add)
{
    ss << add;
}

std::string StringStream::getString()
{
    return ss.str();
}

