CREATE OR REPLACE PACKAGE BODY ph_crypto 
IS

    ---------------------------------------------------------------------------
    --
    -- PACKAGE NOTES
    --
    -- PH_CRYPTO is rebuild from the Oracle system package DBMS_CRYPTO. 
	-- PH_CRYPTO contains basic cryptographic functions and
    -- procedures.  To use correctly and securely, a general level of
    -- security expertise is assumed.
    --
    -- In DBMS_CRYPTO, VARCHAR2 datatype is not supported. Cryptographic 
    -- operations on this type should be prefaced with conversions to a 
    -- uniform character set (AL32UTF8) and conversion to RAW type. In 
	-- PH_CRYPTO, VARCHAR2 datatype, NUMBER datatype and DATE datatype is 
	-- supported by rebuilding the DBMS_CRYPTO.
    --
    -- Currently, we don't have the LOB date. So LOB datatype is not supported.
	-- But i leave the interface to rebuild the fucntion to deal with the LOB 
	-- datatype. Prior to encryption, hashing or keyed hashing, CLOB datatype  
    -- should be converted to AL32UTF8.  This allows cryptographic data to be
    -- transferred and understood between databases with different
    -- character sets, across character set changes and between
    -- separate processes (for example, Java programs).
    --
    ---------------------------------------------------------------------------


    -------------------------- ALGORITHM CONSTANTS ----------------------------
    -- The following constants refer to various types of cryptographic
    -- functions available from this package.  Some of the constants
    -- represent modifiers to these algorithms.
    ---------------------------------------------------------------------------
    
    MAX_RAW_SIZE CONSTANT PLS_INTEGER := 32767;

	
	
	
	---------------------- FUNCTIONS AND PROCEDURES ------------------------

    ------------------------------------------------------------------------
    --
    -- NAME:  Encrypt
    --
    -- DESCRIPTION:
    --
    --   Encrypt plain text data using stream or block cipher with user
    --   supplied key and optional iv.
    --
    -- PARAMETERS
    --
    --   plaintext   - Plaintext data to be encrypted
    --   crypto_type - Stream or block cipher type plus modifiers
    --   key         - Key to be used for encryption
    --   iv          - Optional IV for block ciphers.  Default all zeros.
    --
    -- USAGE NOTES:
    --
    --   Block ciphers may be modified with chaining type (CBC most
    --   common) and padding type (PKCS5 recommended).  Of the four
    --   common data formats, three have been provided: RAW, BLOB,
    --   CLOB. For VARCHAR2 encryption, callers should first convert
    --   to AL32UTF8 character set and then encrypt.
    --
    --     Encrypt(UTL_RAW.CAST_TO_RAW(CONVERT(src,'AL32UTF8')),typ,key);
    --
    --   As return type for encrypt is RAW, callers should consider
    --   encoding it with RAWTOHEX or UTL_ENCODE.BASE64_ENCODE to make
    --   it suitable for VARCHAR2 storage.  These functions expand
    --   data size by 2 and 4/3, respectively.
    --
    --   To improve readability, callers should define their own
    --   package level constants to represent the ciphersuites used
    --   for encryption and decryption.
    --
    --   For example:
    --
    --   DES_CBC_PKCS5 CONSTANT PLS_INTEGER := PH_CRYPTO.ENCRYPT_DES
    --                                       + PH_CRYPTO.CHAIN_CBC
    --                                       + PH_CRYPTO.PAD_PKCS5;
    --
    --
    -- STREAM CIPHERS (RC4) ARE NOT RECOMMENDED FOR STORED DATA ENCRYPTION.
    --
    --
    ------------------------------------------------------------------------
    FUNCTION  encrypt (
		src IN            RAW
	,	typ IN            PLS_INTEGER
	,	key IN            RAW
	,	iv  IN            RAW          DEFAULT NULL
	) RETURN RAW IS
    BEGIN
		RETURN SYS.DBMS_CRYPTO_FFI.ENCRYPT(src, typ, key, IV);
    END encrypt;

	
    PROCEDURE encrypt (
		dst IN OUT NOCOPY BLOB
	,	src IN            BLOB
	,	typ IN            PLS_INTEGER
	,	key IN            RAW
	,	iv  IN            RAW          DEFAULT NULL
	) IS
    BEGIN
      SYS.DBMS_CRYPTO_FFI.ENCRYPT(dst, src, typ, key, iv);
    END encrypt;

	
    PROCEDURE encrypt (
		DST IN OUT NOCOPY BLOB
	,	src IN            CLOB         CHARACTER SET ANY_CS
	,	typ IN            PLS_INTEGER
	,	key IN            RAW
	,	iv  IN            RAW          DEFAULT NULL
	) IS
    BEGIN
      SYS.DBMS_CRYPTO_FFI.ENCRYPT(dst, src, typ, key, iv);
    END encrypt;


		FUNCTION encrypt(
		p_input_str IN VARCHAR2 
	,	p_key_str	IN VARCHAR2
	) RETURN RAW 
	IS
		encryption_mode     NUMBER := PH_CRYPTO.DES_CBC_PKCS5;
		encrypted_raw       RAW(2000) := NULL;
	BEGIN
		encrypted_raw := 
			PH_CRYPTO.ENCRYPT(
				UTL_I18N.STRING_TO_RAW(p_input_str, 'AL32UTF8')
			,   encryption_mode
			,   UTL_I18N.STRING_TO_RAW(p_key_str, 'AL32UTF8'));

		RETURN encrypted_raw;
	END encrypt;


	FUNCTION encrypt(
		p_input_dt  IN DATE 
	,	p_key_str	IN VARCHAR2
	) RETURN RAW 
	IS
		encryption_mode     NUMBER := PH_CRYPTO.DES_CBC_PKCS5;
		encrypted_raw       RAW(2000) := NULL;
	BEGIN
		encrypted_raw := 
			PH_CRYPTO.ENCRYPT(
				UTL_I18N.STRING_TO_RAW(TO_CHAR(p_input_dt, 'YYYYMMDDHH24MISS'), 'AL32UTF8')
			,   encryption_mode
			,   UTL_I18N.STRING_TO_RAW(p_key_str, 'AL32UTF8'));

		RETURN encrypted_raw;
	END encrypt;


	FUNCTION encrypt(
		p_input_num  IN NUMBER 
	,	p_key_str	 IN VARCHAR2
	) RETURN RAW 
	IS
		encryption_mode     NUMBER := PH_CRYPTO.DES_CBC_PKCS5;
		encrypted_raw       RAW(2000) := NULL;
	BEGIN
		encrypted_raw := 
			PH_CRYPTO.ENCRYPT(
				UTL_I18N.STRING_TO_RAW(TO_CHAR(p_input_num), 'AL32UTF8')
			,   encryption_mode
			,   UTL_I18N.STRING_TO_RAW(p_key_str, 'AL32UTF8')
		);
		RETURN encrypted_raw;
	END encrypt;
	

	
	-----------------------------------------------------------------------
    --
    -- NAME:  Decrypt
    --
    -- DESCRIPTION:
    --
    --   Decrypt crypt text data using stream or block cipher with user
    --   supplied key and optional iv.
    --
    -- PARAMETERS
    --
    --   cryptext    - Crypt text data to be decrypted
    --   crypto_type - Stream or block cipher type plus modifiers
    --   key         - Key to be used for encryption
    --   iv          - Optional IV for block ciphers.  Default all zeros.
    --
    -- USAGE NOTES:
    --   To retrieve original plain text data, Decrypt must be called
    --   with the same cipher, modifiers, key and iv used for
    --   encryption.  If crypt text data was converted to hex or
    --   base64 prior to storage, it must be decoded using HEXTORAW or
    --   UTL_ENCODE.BASE64_DECODE prior to decryption.
    --
    ------------------------------------------------------------------------
	
	
    FUNCTION  decrypt (
		src IN            RAW
	,	TYP IN            PLS_INTEGER
	,	KEY IN            RAW
	,	IV  IN            RAW          DEFAULT NULL
	) RETURN RAW IS
    BEGIN
		RETURN SYS.DBMS_CRYPTO_FFI.DECRYPT(src, typ, key, iv);
    END decrypt;

	
    PROCEDURE decrypt (
		DST IN OUT NOCOPY BLOB
	,	src IN            BLOB
	,	TYP IN            PLS_INTEGER
	,	KEY IN            RAW
	,	IV  IN            RAW          DEFAULT NULL
	) IS
    BEGIN
		SYS.DBMS_CRYPTO_FFI.DECRYPT(dst, src, typ, key, iv);
    END decrypt;

	
    PROCEDURE decrypt (
		dst IN OUT NOCOPY CLOB         CHARACTER SET ANY_CS
	,	src IN            BLOB
	,	typ IN            PLS_INTEGER
	,	key IN            RAW
	,	iv  IN            RAW          DEFAULT NULL
	) IS
    BEGIN
      SYS.DBMS_CRYPTO_FFI.DECRYPT(dst, src, typ, key, iv);
    END decrypt;

	
	FUNCTION str_dencrypt(
		p_input_raw IN RAW 
	,	p_key_str	IN VARCHAR2
	) RETURN VARCHAR2 
	IS
		encryption_mode     NUMBER := PH_CRYPTO.DES_CBC_PKCS5;
		decrypted_raw       RAW(2000) := NULL;
		output_string       VARCHAR2(2000) := NULL;
	BEGIN
		decrypted_raw := 
			PH_CRYPTO.DECRYPT(
				p_input_raw
			,   encryption_mode
			,   UTL_I18N.STRING_TO_RAW(p_key_str, 'AL32UTF8'));
		output_string := UTL_I18N.RAW_TO_CHAR(decrypted_raw, 'AL32UTF8');
		--DBMS_OUTPUT.PUT_LINE('Decrypted char value : ' || output_string);
		RETURN output_string;
	END str_dencrypt;

	FUNCTION num_dencrypt(
		p_input_raw IN RAW 
	,	p_key_str	IN VARCHAR2
	) RETURN NUMBER 
	IS
		encryption_mode     NUMBER := PH_CRYPTO.DES_CBC_PKCS5;
		decrypted_raw       RAW(2000) := NULL;
		output_string       NUMBER := NULL;
	BEGIN
		decrypted_raw := 
			PH_CRYPTO.DECRYPT(
				p_input_raw
			,   encryption_mode
			,   UTL_I18N.STRING_TO_RAW(p_key_str, 'AL32UTF8'));
		output_string := TO_NUMBER(UTL_I18N.RAW_TO_CHAR(decrypted_raw, 'AL32UTF8'));
		--DBMS_OUTPUT.PUT_LINE('Decrypted char value : ' || output_string);
		RETURN output_string;
	END num_dencrypt;

	FUNCTION dt_dencrypt(
		p_input_raw IN RAW 
	,	p_key_str	IN VARCHAR2
	) RETURN DATE 
	IS
		encryption_mode     NUMBER := PH_CRYPTO.DES_CBC_PKCS5;
		decrypted_raw       RAW(2000) := NULL;
		output_string       DATE := NULL;
	BEGIN
		decrypted_raw := 
			PH_CRYPTO.DECRYPT(
				p_input_raw
			,   encryption_mode
			,   UTL_I18N.STRING_TO_RAW(p_key_str, 'AL32UTF8'));
		output_string := TO_DATE(UTL_I18N.RAW_TO_CHAR(decrypted_raw, 'AL32UTF8'), 'YYYYMMDDHH24MISS');
		--DBMS_OUTPUT.PUT_LINE('Decrypted char value : ' || output_string);
		RETURN output_string;
	END dt_dencrypt;

	
	
	
	
	------------------------------------------------------------------------
    --
    -- NAME:  Hash
    --
    -- DESCRIPTION:
    --
    --   Hash source data by cryptographic hash type.
    --
    -- PARAMETERS
    --
    --   source    - Source data to be hashed
    --   hash_type - Hash algorithm to be used
    --
    -- USAGE NOTES:
    --   SHA-1 (HASH_SH1) is recommended.  Consider encoding returned
    --   raw value to hex or base64 prior to storage.
    --
    ------------------------------------------------------------------------
	
	
    FUNCTION hash (
		src IN RAW
	,	typ IN PLS_INTEGER
	) RETURN RAW IS
    BEGIN
		RETURN SYS.DBMS_CRYPTO_FFI.HASH(src, typ);
    END hash;

    FUNCTION hash (
		src IN BLOB
	,	TYP IN PLS_INTEGER
	)
		RETURN RAW IS
    BEGIN
  		RETURN SYS.DBMS_CRYPTO_FFI.HASH(src, typ);
    END hash;

    FUNCTION hash (
		src IN CLOB        CHARACTER SET ANY_CS
	,	TYP IN PLS_INTEGER
	) RETURN RAW IS
    BEGIN
  		RETURN SYS.DBMS_CRYPTO_FFI.HASH(src, typ);
    END hash;

	------------------------------------------------------------------------
    --
    -- NAME:  RandomBytes
    --
    -- DESCRIPTION:
    --
    --   Returns a raw value containing a pseudo-random sequence of
    --   bytes.
    --
    -- PARAMETERS
    --
    --   number_bytes - Number of pseudo-random bytes to be generated.
    --
    -- USAGE NOTES:
    --   number_bytes should not exceed maximum RAW length.
    --
    ------------------------------------------------------------------------
	
	FUNCTION randombytes(
		NUMBER_BYTES IN PLS_INTEGER
	) RETURN RAW IS
	BEGIN
		IF NUMBER_BYTES < MAX_RAW_SIZE THEN
			RETURN SYS.DBMS_CRYPTO_FFI.RANDOM(number_bytes);
		ELSE 
			RAISE VALUE_ERROR;
		END IF;
    END randombytes;

	
	
	------------------------------------------------------------------------
    --
    -- NAME:  RandomNumber
    --
    -- DESCRIPTION:
    --
    --   Returns a random Oracle Number.
    --
    -- PARAMETERS
    --
    --  None.
    --
    ------------------------------------------------------------------------
	
	
    FUNCTION randomnumber
		RETURN NUMBER IS
    BEGIN
		RETURN TO_NUMBER(
			RAWTOHEX(SYS.DBMS_CRYPTO_FFI.RANDOM(16))
		,	'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
		);
    END randomnumber;

	
	
	------------------------------------------------------------------------
    --
    -- NAME:  RandomInteger
    --
    -- DESCRIPTION:
    --
    --   Returns a random BINARY_INTEGER.
    --
    -- PARAMETERS
    --
    --  None.
    --
    ------------------------------------------------------------------------	
	
	
    FUNCTION randominteger
		RETURN BINARY_INTEGER IS
    BEGIN
		RETURN UTL_RAW.CAST_TO_BINARY_INTEGER(SYS.DBMS_CRYPTO_FFI.RANDOM(4));
    END randominteger;

	--==========================================================================================
	


	
END ph_crypto;
/

show error
