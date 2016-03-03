CREATE OR REPLACE PACKAGE crypto_system
IS
	------------------------------------------------------------------------
    --
    -- NAME:  check_configuartion
    --
    -- DESCRIPTION:
    --
    --   Check point:
	--      1. for one table, crypto_configuartion can only have one load_type
    --		2. owner name, table name and column is correct
	-- 		3. target schema has the privilege to read the source table
	-- 		4. check whether the target column datatype is RAW
	-- 		5. check the datatype on which column is not encrypted
	-- 
    -- PARAMETERS
    --
    --  None.
    --
    ------------------------------------------------------------------------
	
	
	PROCEDURE check_configuartion;
	
	
	------------------------------------------------------------------------
    --
    -- NAME:  log_recorder
    --
    -- DESCRIPTION:
    --
    --   Log system. Write the log in crypto_log
	--      

	-- 
    -- PARAMETERS
    --
    --  None.
    --
    ------------------------------------------------------------------------
	PROCEDURE log_recorder;
	
	
	------------------------------------------------------------------------
    --
    -- NAME:  encrypt_all
    --
    -- DESCRIPTION:
    -- 
	--   0. run check_configuartion to verficate the correctness 
    --   1. generate the insert statement according the crypto_configuartion
	--   2. execute the insert statement
	-- 
	-- 
    -- PARAMETERS
    --
    --  p_key_str
    --
    ------------------------------------------------------------------------
	PROCEDURE encrypt_all(
		p_key_str	IN VARCHAR2
	);

END crypto_system;
/





