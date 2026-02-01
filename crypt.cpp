#include "exception.h"
#include "crypt.h"

#include <string>
#include <boost/format.hpp>

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>

namespace Crypt
{
	Generic::Generic() :
		active(false)
	{
	}

	Generic::~Generic()
	{
	}

	CRC32::CRC32() :
		crc(0),
		checksummed(0)
	{
	}

	CRC32::~CRC32()
	{
	}

	void CRC32::init(bool, std::string_view initial)
	{
		if(this->active)
			throw(hard_exception("CRC32::init: already active"));

		if(!initial.empty())
		{
			if(initial.size() != 4)
				throw(hard_exception("CRC32::init: initial CRC size != 4"));

			this->crc = string_to_uint32(initial);
		}
		else
			this->crc = 0xffffffffUL;

		this->checksummed = 0;
		this->active = true;
	}

	std::string CRC32::update(std::string_view data)
	{
		static constexpr uint32_t crc32_table[] =
		{
			0xb1f7404b, 0xb5365dfc, 0xb8757b25, 0xbcb46692, 0xa2f33697, 0xa6322b20,
			0xab710df9, 0xafb0104e, 0x97ffadf3, 0x933eb044, 0x9e7d969d, 0x9abc8b2a,
			0x84fbdb2f, 0x803ac698, 0x8d79e041, 0x89b8fdf6, 0xfde69b3b, 0xf927868c,
			0xf464a055, 0xf0a5bde2, 0xeee2ede7, 0xea23f050, 0xe760d689, 0xe3a1cb3e,
			0xdbee7683, 0xdf2f6b34, 0xd26c4ded, 0xd6ad505a, 0xc8ea005f, 0xcc2b1de8,
			0xc1683b31, 0xc5a92686, 0x29d4f6ab, 0x2d15eb1c, 0x2056cdc5, 0x2497d072,
			0x3ad08077, 0x3e119dc0, 0x3352bb19, 0x3793a6ae, 0x0fdc1b13, 0x0b1d06a4,
			0x065e207d, 0x029f3dca, 0x1cd86dcf, 0x18197078, 0x155a56a1, 0x119b4b16,
			0x65c52ddb, 0x6104306c, 0x6c4716b5, 0x68860b02, 0x76c15b07, 0x720046b0,
			0x7f436069, 0x7b827dde, 0x43cdc063, 0x470cddd4, 0x4a4ffb0d, 0x4e8ee6ba,
			0x50c9b6bf, 0x5408ab08, 0x594b8dd1, 0x5d8a9066, 0x8571303c, 0x81b02d8b,
			0x8cf30b52, 0x883216e5, 0x967546e0, 0x92b45b57, 0x9ff77d8e, 0x9b366039,
			0xa379dd84, 0xa7b8c033, 0xaafbe6ea, 0xae3afb5d, 0xb07dab58, 0xb4bcb6ef,
			0xb9ff9036, 0xbd3e8d81, 0xc960eb4c, 0xcda1f6fb, 0xc0e2d022, 0xc423cd95,
			0xda649d90, 0xdea58027, 0xd3e6a6fe, 0xd727bb49, 0xef6806f4, 0xeba91b43,
			0xe6ea3d9a, 0xe22b202d, 0xfc6c7028, 0xf8ad6d9f, 0xf5ee4b46, 0xf12f56f1,
			0x1d5286dc, 0x19939b6b, 0x14d0bdb2, 0x1011a005, 0x0e56f000, 0x0a97edb7,
			0x07d4cb6e, 0x0315d6d9, 0x3b5a6b64, 0x3f9b76d3, 0x32d8500a, 0x36194dbd,
			0x285e1db8, 0x2c9f000f, 0x21dc26d6, 0x251d3b61, 0x51435dac, 0x5582401b,
			0x58c166c2, 0x5c007b75, 0x42472b70, 0x468636c7, 0x4bc5101e, 0x4f040da9,
			0x774bb014, 0x738aada3, 0x7ec98b7a, 0x7a0896cd, 0x644fc6c8, 0x608edb7f,
			0x6dcdfda6, 0x690ce011, 0xd8fba0a5, 0xdc3abd12, 0xd1799bcb, 0xd5b8867c,
			0xcbffd679, 0xcf3ecbce, 0xc27ded17, 0xc6bcf0a0, 0xfef34d1d, 0xfa3250aa,
			0xf7717673, 0xf3b06bc4, 0xedf73bc1, 0xe9362676, 0xe47500af, 0xe0b41d18,
			0x94ea7bd5, 0x902b6662, 0x9d6840bb, 0x99a95d0c, 0x87ee0d09, 0x832f10be,
			0x8e6c3667, 0x8aad2bd0, 0xb2e2966d, 0xb6238bda, 0xbb60ad03, 0xbfa1b0b4,
			0xa1e6e0b1, 0xa527fd06, 0xa864dbdf, 0xaca5c668, 0x40d81645, 0x44190bf2,
			0x495a2d2b, 0x4d9b309c, 0x53dc6099, 0x571d7d2e, 0x5a5e5bf7, 0x5e9f4640,
			0x66d0fbfd, 0x6211e64a, 0x6f52c093, 0x6b93dd24, 0x75d48d21, 0x71159096,
			0x7c56b64f, 0x7897abf8, 0x0cc9cd35, 0x0808d082, 0x054bf65b, 0x018aebec,
			0x1fcdbbe9, 0x1b0ca65e, 0x164f8087, 0x128e9d30, 0x2ac1208d, 0x2e003d3a,
			0x23431be3, 0x27820654, 0x39c55651, 0x3d044be6, 0x30476d3f, 0x34867088,
			0xec7dd0d2, 0xe8bccd65, 0xe5ffebbc, 0xe13ef60b, 0xff79a60e, 0xfbb8bbb9,
			0xf6fb9d60, 0xf23a80d7, 0xca753d6a, 0xceb420dd, 0xc3f70604, 0xc7361bb3,
			0xd9714bb6, 0xddb05601, 0xd0f370d8, 0xd4326d6f, 0xa06c0ba2, 0xa4ad1615,
			0xa9ee30cc, 0xad2f2d7b, 0xb3687d7e, 0xb7a960c9, 0xbaea4610, 0xbe2b5ba7,
			0x8664e61a, 0x82a5fbad, 0x8fe6dd74, 0x8b27c0c3, 0x956090c6, 0x91a18d71,
			0x9ce2aba8, 0x9823b61f, 0x745e6632, 0x709f7b85, 0x7ddc5d5c, 0x791d40eb,
			0x675a10ee, 0x639b0d59, 0x6ed82b80, 0x6a193637, 0x52568b8a, 0x5697963d,
			0x5bd4b0e4, 0x5f15ad53, 0x4152fd56, 0x4593e0e1, 0x48d0c638, 0x4c11db8f,
			0x384fbd42, 0x3c8ea0f5, 0x31cd862c, 0x350c9b9b, 0x2b4bcb9e, 0x2f8ad629,
			0x22c9f0f0, 0x2608ed47, 0x1e4750fa, 0x1a864d4d, 0x17c56b94, 0x13047623,
			0x0d432626, 0x09823b91, 0x04c11d48, 0x000000ff
		};

		unsigned int value;

		if(!this->active)
			throw(hard_exception("CRC32::update: not active"));

		for(std::string_view::const_iterator it = data.begin(); it != data.end(); it++, this->checksummed++)
		{
			value = static_cast<unsigned int>(*it) & 0xff;
			this->crc = (this->crc << 8) ^ crc32_table[((this->crc >> 24) ^ value) & 0xff];
		}

		return(uint32_to_string(this->crc));
	}

	std::string CRC32::finish()
	{
		unsigned int padding_amount;
		std::string padding;

		if(!this->active)
			throw(hard_exception("CRC32::finish: not active"));

		padding_amount = (4 - (this->checksummed & 0x03)) & 0x03;

		padding.assign(padding_amount, static_cast<char>(0x00));

		this->update(padding);

		this->active = false;

		return(uint32_to_string(this->crc));
	}

	SHA256::SHA256()
	{
	}

	SHA256::~SHA256()
	{
	}

	void SHA256::init(bool, std::string_view)
	{
		const mbedtls_md_info_t *info;

		if(this->active)
			throw(hard_exception("SHA256::init: already active"));

		if(!(info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256)))
			throw(hard_exception("SHA256::init: error in mbedtls_md_info_from_type"));

		mbedtls_md_init(&this->ctx);

		if(mbedtls_md_setup(&this->ctx, info, /* do not enable HMAC */ 0))
		{
			mbedtls_md_free(&this->ctx);
			throw(hard_exception("SHA256::init: error in mbedtls_md_setup"));
		}

		if(mbedtls_md_starts(&this->ctx))
		{
			mbedtls_md_free(&this->ctx);
			throw(hard_exception("SHA256::init: error in mbedtls_starts"));
		}

		this->active = true;
	}

	std::string SHA256::update(std::string_view in)
	{
		if(!this->active)
			throw(hard_exception("SHA256::update: not active"));

		if(mbedtls_md_update(&this->ctx, reinterpret_cast<const unsigned char *>(in.data()), in.size()))
		{
			mbedtls_md_free(&this->ctx);
			this->active = false;
			throw(hard_exception("SHA256::update: error in mbedtls_update"));
		}

		return("");
	}

	std::string SHA256::finish()
	{
		std::string out;

		if(!this->active)
			throw(hard_exception("SHA256::finish: not active"));

		out.resize(256 / 8);

		if(mbedtls_md_finish(&this->ctx, reinterpret_cast<unsigned char *>(out.data())))
		{
			mbedtls_md_free(&this->ctx);
			this->active = false;
			throw(hard_exception("SHA256::finish: error in mbedtls_finish"));
		}

		mbedtls_md_free(&this->ctx);

		this->active = false;

		return(out);
	}

	AES256::AES256()
	{
	}

	AES256::~AES256()
	{
	}

	void AES256::init(bool encrypt, std::string_view key)
	{
		static constexpr uint8_t init_vector[16] = { 0x5f, 0x8e, 0xee, 0x60, 0xf9, 0x56, 0x4d, 0xff, 0x82, 0xf1, 0x8a, 0xf5, 0x8d, 0x1c, 0x08, 0xe6 };

		const mbedtls_cipher_info_t *info;

		if(this->active)
			throw(hard_exception("AES256::init: already active"));

		if(key.size() != (256 / 8))
			throw(hard_exception("AES256::init: invalid binary key length"));

		if(!(info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC)))
			throw(hard_exception("AES256::init: error in mbedtls_cipher_info_from_type"));

		try
		{
			mbedtls_cipher_init(&this->ctx);

			if(mbedtls_cipher_setup(&this->ctx, info))
				throw(hard_exception("AES256::init: error in mbedtls_cipher_setup"));

			if(mbedtls_cipher_setkey(&this->ctx, reinterpret_cast<const unsigned char *>(key.data()), key.size() * 8, encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT) != 0)
				throw(hard_exception("AES256::init: error in mbedtls_cipher_setkey"));

			if(mbedtls_cipher_set_padding_mode(&this->ctx, MBEDTLS_PADDING_PKCS7))
				throw(hard_exception("AES256::init: error in mbedtls_cipher_set_padding_mode"));

			if(mbedtls_cipher_reset(&this->ctx))
				throw(hard_exception("AES256::init: error in mbedtls_cipher_reset"));

			if(mbedtls_cipher_set_iv(&this->ctx, init_vector, sizeof(init_vector)))
				throw(hard_exception("AES256::init: error in mbedtls_cipher_set_iv"));

		}
		catch(const hard_exception &e)
		{
			mbedtls_cipher_free(&this->ctx);
			throw;
		}

		this->active = true;
	}

	std::string AES256::update(std::string_view in)
	{
		std::string out;
		size_t outlen;

		if(!this->active)
			throw(hard_exception("AES256::update: not active"));

		out.resize(in.size() + 32);
		outlen = out.size();

		if(mbedtls_cipher_update(&this->ctx, reinterpret_cast<const unsigned char *>(in.data()), in.size(), reinterpret_cast<unsigned char *>(out.data()), &outlen))
		{
			mbedtls_cipher_free(&this->ctx);
			this->active = false;
			throw(hard_exception("AES256::update: error in mbedtls_cipher_update"));
		}

		out.resize(outlen);

		return(out);
	}

	std::string AES256::finish()
	{
		std::string out;
		size_t outlen;
		int rv;

		if(!this->active)
			throw(hard_exception("AES256::finish: not active"));

		out.resize(32);
		outlen = out.size();

		if(!!(rv = mbedtls_cipher_finish(&this->ctx, reinterpret_cast<unsigned char *>(out.data()), &outlen)))
		{
			mbedtls_cipher_free(&this->ctx);
			this->active = false;
			throw(hard_exception(std::format("AES256::finish: error in mbedtls_cipher_finish: {:#x}", rv)));
		}

		out.resize(outlen);

		mbedtls_cipher_free(&this->ctx);
		this->active = false;

		return(out);
	}

	std::string password_to_aes256_key(std::string_view password)
	{
		static constexpr uint8_t password_salt[4] = { 0x4a, 0xfb, 0xfc, 0x55 };

		std::string salted_password;

		salted_password.assign(reinterpret_cast<const char *>(password_salt), sizeof(password_salt));
		salted_password.append(password);
		return(sha256(salted_password));
	}

	std::string hash_to_text(std::string_view hash)
	{
		char raw_value;
		unsigned int current, value;
		std::string hash_string;

		for(current = 0; current < hash.size(); current++)
		{
			raw_value = hash.at(current);
			value = static_cast<unsigned int>(raw_value) & 0xff;
			hash_string.append((boost::format("%02x") % value).str());
		}

		return(hash_string);
	}

	std::string uint32_to_string(uint32_t in)
	{
		std::string out;

		for(int byte = 3; byte >= 0; byte--)
		{
			out.append(1, (static_cast<unsigned int>(in) & 0xff000000) >> 24);
			in <<= 8;
		}

		return(out);
	}

	uint32_t string_to_uint32(std::string_view in)
	{
		uint32_t out = 0;

		for(std::string_view::const_iterator it = in.begin(); it != in.end(); it++)
		{
			out <<= 8;
			out |= static_cast<unsigned int>(*it) & 0xff;
		}

		return(out);
	}


	uint32_t crc32(std::string_view in)
	{
		CRC32 crc;

		crc.init();
		crc.update(in);
		return(string_to_uint32(crc.finish()));
	}

	std::string sha256(std::string_view in)
	{
		Crypt::SHA256 sha;

		sha.init();
		sha.update(in);
		return(sha.finish());
	}

	std::string aes256(bool encrypt, std::string_view key, std::string_view in)
	{
		Crypt::AES256 aes;
		std::string out;

		aes.init(encrypt, key);
		out.assign(aes.update(in));
		out.append(aes.finish());

		return(out);
	}
};
