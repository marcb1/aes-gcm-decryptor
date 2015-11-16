#pragma once

/*
 * interface used by encryptor to read and write cipher/plain text.
 */
class IStream
{
public:

  virtual ~IStream(){}

  virtual int writeBuf(const unsigned char* buf, unsigned int size) = 0;

  // read into buf size bytes
  virtual int readBuf(unsigned char* buf, unsigned int size) = 0;

  virtual unsigned int getSize() = 0;
};
