#pragma once

#include "IStream.h"
#include "helpers.h"

class FileStream: public IStream
{
  private:
    int _fd;

  public:
    FileStream():
      _fd(-1){}

    virtual ~FileStream()
    {
      if(_fd != -1)
      {
        close(_fd);
      }
    }

    bool openFile(const char* fileName, int flags)
    {
      _fd = open(fileName, flags, 0600);
      if(_fd == -1)
      {
        std::cerr << "Couldn't open input file" << std::endl;
        return false;
      }
      return true;
    }
    off_t getSize()
    {
      off_t file_len = getFileSize(_fd);
      return file_len;
    }

    int writeBuf(const unsigned char* buf, unsigned int size)
    {
      return write(_fd, buf, size);
    }

    int readBuf(unsigned char* buf, unsigned int size)
    {
      return read(_fd, buf, size);
    }
};
