CREATE OR REPLACE PACKAGE ph_crypto 
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

    -- Hash Functions
    HASH_MD4           CONSTANT PLS_INTEGER            :=     1;
    HASH_MD5           CONSTANT PLS_INTEGER            :=     2;
    HASH_SH1           CONSTANT PLS_INTEGER            :=     3;

    -- MAC Functions
    HMAC_MD5           CONSTANT PLS_INTEGER            :=     1;
    HMAC_SH1           CONSTANT PLS_INTEGER            :=     2;

    -- Block Cipher Algorithms
    ENCRYPT_DES        CONSTANT PLS_INTEGER            :=     1;  -- 0x0001
    ENCRYPT_3DES_2KEY  CONSTANT PLS_INTEGER            :=     2;  -- 0x0002
    ENCRYPT_3DES       CONSTANT PLS_INTEGER            :=     3;  -- 0x0003
    ENCRYPT_AES        CONSTANT PLS_INTEGER            :=     4;  -- 0x0004
    ENCRYPT_PBE_MD5DES CONSTANT PLS_INTEGER            :=     5;  -- 0x0005
    ENCRYPT_AES128     CONSTANT PLS_INTEGER            :=     6;  -- 0x0006
    ENCRYPT_AES192     CONSTANT PLS_INTEGER            :=     7;  -- 0x0007
    ENCRYPT_AES256     CONSTANT PLS_INTEGER            :=     8;  -- 0x0008

    -- Block Cipher Chaining Modifiers
    CHAIN_CBC          CONSTANT PLS_INTEGER            :=   256;  -- 0x0100
    CHAIN_CFB          CONSTANT PLS_INTEGER            :=   512;  -- 0x0200
    CHAIN_ECB          CONSTANT PLS_INTEGER            :=   768;  -- 0x0300
    CHAIN_OFB          CONSTANT PLS_INTEGER            :=  1024;  -- 0x0400

    -- Block Cipher Padding Modifiers
    PAD_PKCS5          CONSTANT PLS_INTEGER            :=  4096;  -- 0x1000
    PAD_NONE           CONSTANT PLS_INTEGER            :=  8192;  -- 0x2000
    PAD_ZERO           CONSTANT PLS_INTEGER            := 12288;  -- 0x3000
    PAD_ORCL           CONSTANT PLS_INTEGER            := 16384;  -- 0x4000

    -- Stream Cipher Algorithms
    ENCRYPT_RC4        CONSTANT PLS_INTEGER            :=   129;  -- 0x0081


    -- Convenience Constants for Block Ciphers
    DES_CBC_PKCS5      CONSTANT PLS_INTEGER            := ENCRYPT_DES
                                                          + CHAIN_CBC
                                                          + PAD_PKCS5;

    DES3_CBC_PKCS5     CONSTANT PLS_INTEGER            := ENCRYPT_3DES
                                                          + CHAIN_CBC
                                                          + PAD_PKCS5;

    AES_CBC_PKCS5      CONSTANT PLS_INTEGER            := ENCRYPT_AES
                                                          + CHAIN_CBC
                                                          + PAD_PKCS5;


    ----------------------------- EXCEPTIONS ----------------------------------
    -- Invalid Cipher Suite
    ciphersuiteinvalid EXCEPTION;
    PRAGMA EXCEPTION_INIT(ciphersuiteinvalid, -28827);

    -- Null Cipher Suite
    ciphersuitenull EXCEPTION;
    PRAGMA EXCEPTION_INIT(ciphersuitenull,    -28829);

    -- Key Null
    keynull EXCEPTION;
    PRAGMA EXCEPTION_INIT(keynull,            -28239);

    -- Key Bad Size
    keybadsize EXCEPTION;
    PRAGMA EXCEPTION_INIT(keybadsize,         -28234);

    -- Double Encryption
    doubleencryption EXCEPTION;
    PRAGMA EXCEPTION_INIT(doubleencryption,   -28233);

	
	
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
	) RETURN RAW;

    PROCEDURE encrypt (
		dst IN OUT NOCOPY BLOB
	,	src IN            BLOB
	,	typ IN            PLS_INTEGER
	,	key IN            RAW
	,	iv  IN            RAW          DEFAULT NULL
	);

    PROCEDURE encrypt (
		dst IN OUT NOCOPY BLOB
	,	src IN            CLOB         CHARACTER SET ANY_CS
	,	typ IN            PLS_INTEGER
	,	key IN            RAW
	,	iv  IN            RAW          DEFAULT NULL
	);

	FUNCTION encrypt(
		p_input_str IN VARCHAR2 
	,	p_key_str	IN VARCHAR2
	) RETURN RAW;
	
	FUNCTION encrypt(
		p_input_dt  IN DATE 
	,	p_key_str	IN VARCHAR2
	) RETURN RAW;
	
	FUNCTION encrypt(
		p_input_num  IN NUMBER 
	,	p_key_str	 IN VARCHAR2
	) RETURN RAW;
	
	
	
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
	,	typ IN            PLS_INTEGER
	,	key IN            RAW
	,	iv  IN            RAW          DEFAULT NULL
	) RETURN RAW;

    PROCEDURE decrypt (
		dst IN OUT NOCOPY BLOB
	,	src IN            BLOB
	,	typ IN            PLS_INTEGER
	,	key IN            RAW
	,	iv  IN            RAW          DEFAULT NULL
	);

    PROCEDURE decrypt (
		dst IN OUT NOCOPY CLOB         CHARACTER SET ANY_CS
	,	src IN            BLOB
	,	typ IN            PLS_INTEGER
	,	key IN            RAW
	,	iv  IN            RAW          DEFAULT NULL
	);

	FUNCTION str_dencrypt(
		p_input_raw IN RAW 
	,	p_key_str	IN VARCHAR2
	) RETURN VARCHAR2;

	FUNCTION num_dencrypt(
		p_input_raw IN RAW 
	,	p_key_str	IN VARCHAR2
	) RETURN NUMBER;

	FUNCTION dt_dencrypt(
		p_input_raw IN RAW 
	,	p_key_str	IN VARCHAR2
	) RETURN DATE;
	
	
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
	) RETURN RAW DETERMINISTIC;

    FUNCTION hash (
		src IN BLOB
	,	typ IN PLS_INTEGER
	) RETURN RAW DETERMINISTIC;

    FUNCTION hash (
		src IN CLOB        CHARACTER SET ANY_CS
	,	typ IN PLS_INTEGER
	) RETURN RAW DETERMINISTIC;

	
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
    FUNCTION randombytes (
		number_bytes IN PLS_INTEGER
	) RETURN RAW;
	
	
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
    FUNCTION randomnumber RETURN NUMBER;

	
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
    FUNCTION randominteger RETURN BINARY_INTEGER;


	

	
	-- PRAGMA RESTRICT_REFERENCES(encrypt, WNDS, RNDS, WNPS, RNPS);
	PRAGMA RESTRICT_REFERENCES(decrypt, WNDS, RNDS, WNPS, RNPS);
	PRAGMA RESTRICT_REFERENCES(hash, WNDS, RNDS, WNPS, RNPS);
	PRAGMA RESTRICT_REFERENCES(randombytes, WNDS, RNDS, WNPS, RNPS);
	PRAGMA RESTRICT_REFERENCES(randomnumber, WNDS, RNDS, WNPS, RNPS);
	PRAGMA RESTRICT_REFERENCES(randominteger, WNDS, RNDS, WNPS, RNPS);

END ph_crypto;
/


--=============================================================================================
