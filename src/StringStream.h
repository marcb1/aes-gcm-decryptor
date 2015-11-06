#pragma once

#include "IStream.h"
#include "helpers.h"

class StringStream;
typedef std::shared_ptr<StringStream> StringStreamPtr;

class StringStream: public IStream
{
  private:
    std::stringstream ss;

  public:
    virtual ~StringStream(){}

    int writeBuf(const unsigned char* buf, unsigned int size)
    {
      ss << buf;
      return size;
    }

    int readBuf(unsigned char* buf, unsigned int size)
    {
      std::string currentStream = ss.str();
      if(size > currentStream.size())
      {
        size = currentStream.size();
      }
      strncpy((char*)buf, currentStream.c_str(), size);
      currentStream.erase(0, size);
      ss.str(currentStream);
      return size;
    }

    unsigned int getSize()
    {
        return ss.str().size();
    }

    void addString(const std::string& add)
    {
      ss << add;
    }

    std::string getString()
    {
      return ss.str();
    }
};
