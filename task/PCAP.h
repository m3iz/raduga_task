#pragma once

#include <string>
#include <fstream> 
#include <iostream>

class PCAPReader {
	const std::string fileName;
	bool  rev = false;
	char ch;
	int i = 0;
	int dsize = 0;

private:
	uint32_t reverse(uint32_t x)
	{
		x = (x & 0x00FF00FF) << 8 | (x & 0xFF00FF00) >> 8;
		x = (x & 0x0000FFFF) << 16 | (x & 0xFFFF0000) >> 16;
		return x;
	}
public:
	explicit PCAPReader(const std::string& fileName) {
		typedef struct pcap_hdr_s {
			uint32_t magic_number;  
			uint16_t version_major;  
			uint16_t version_minor; 
			int32_t  thiszone;       
			uint32_t sigfigs;       
			uint32_t snaplen;      
			uint32_t network;        
		} pcap_hdr_t;
		pcap_hdr_t Y;

		typedef struct pcaprec_hdr_s {
			uint32_t ts_sec;        
			uint32_t ts_usec;       
			uint32_t incl_len;       
			uint32_t orig_len;    
		} pcaprec_hdr_t;
		pcaprec_hdr_t X;

		std::ifstream in(fileName, std::ios::binary | (std::ios::in)); 

		in.read((char*)&Y, sizeof Y);
		if (Y.magic_number == 0xA1B2C3D4) rev = true;
		while (1) {

			in.read((char*)&X, sizeof X);
			if ((ch = in.eof()) == true)
				break;

			char buf[65000];
			if (rev) {
				in.read(buf, X.orig_len);
				dsize += X.orig_len;
			}
			else {
				in.read(buf, reverse(X.orig_len));
				dsize += reverse(X.orig_len);
			}
			i++;

		}
		in.close();
	};

	uint64_t packetsCount() const { return i; };

	uint64_t payloadSize() const { return dsize; };
};
