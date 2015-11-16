#include "StringStream.h"

int StringStream::writeBuf(const unsigned char* buf, unsigned int size)
{
    std::string add(reinterpret_cast<const char*>(buf), size);
    _string.append(add);
    return size;
}

int StringStream::readBuf(unsigned char* buf, unsigned int size)
{
    if(size == 0 || _string.size() == 0)
        return 0;
    if(size > _string.size())
    {
        size = _string.size();
    }
    memcpy(buf, _string.c_str(), size);
    _string.erase(0, size);
    return size;
}

unsigned int StringStream::getSize()
{
    return _string.size();
}

void StringStream::addString(const std::string& add)
{
    _string.append(add);
}

std::string StringStream::getString()
{
    return _string;
}
