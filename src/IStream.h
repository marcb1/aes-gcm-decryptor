#pragma once

class IStream
{
public:

  virtual ~IStream(){}

  virtual int writeBuf(const unsigned char* buf, unsigned int size) = 0;

  // read into buf size bytes
  virtual int readBuf(unsigned char* buf, unsigned int size) = 0;
};
