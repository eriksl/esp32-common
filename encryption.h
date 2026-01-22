#pragma once

#include <stdint.h>
#include <string>

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>

class Encryption
{
	public:

		Encryption();
		Encryption(const Encryption &) = delete;
		~Encryption();

		static std::string hash_to_text(std::string_view hash);
		static std::string password_to_aes256_key(std::string_view password);

				void		crc32_init();
				void		crc32_update(std::string_view data);
				uint32_t	crc32_finish();
		static	uint32_t	crc32(std::string_view in);

				void		sha256_init();
				void		sha256_update(std::string_view input);
				std::string	sha256_finish();
		static	std::string	sha256(std::string_view input);

				void		aes256_init(bool encrypt, std::string_view key);
				std::string	aes256_update(std::string_view in);
				std::string	aes256_finish();
		static	std::string	aes256(bool encrypt, std::string_view key, std::string_view input);

		static	std::string	aes256_encrypt(std::string_view key, std::string_view input)
		{
			return(Encryption::aes256(true, key, input));
		}

		static	std::string	aes256_decrypt(std::string_view key, std::string_view input)
		{
			return(Encryption::aes256(false, key, input));
		}

	private:
		
		static const uint32_t crc32_table[];
		static const uint8_t password_salt[4];
		static const uint8_t iv[16];

		uint32_t crc;
		unsigned int checksummed;

		bool sha256_ctx_active;
		mbedtls_md_context_t sha256_ctx;

		bool aes256_ctx_active;
		mbedtls_cipher_context_t aes256_ctx;
};
