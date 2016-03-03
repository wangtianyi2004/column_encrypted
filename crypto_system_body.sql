CREATE OR REPLACE PACKAGE BODY crypto_system
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
	
	
	PROCEDURE check_configuartion
	IS
	BEGIN
		NULL;
	EXCEPTION
		WHEN OTHERS THEN
			RAISE;
	END check_configuartion;
	
	
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
	PROCEDURE log_recorder
	IS
	BEGIN
		NULL;
	EXCEPTION
		WHEN OTHERS THEN
			RAISE;
	END log_recorder;
	
	
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
    --  None.
    --
    ------------------------------------------------------------------------
	PROCEDURE encrypt_all(
		p_key_str	IN VARCHAR2
	)
	IS
	BEGIN
		check_configuartion;
		FOR cur IN(
			SELECT 
				'INSERT INTO ' || target_owner || '.' || targer_table || ' (' || CHR(10) || 
				CHR(9) || LISTAGG(target_column, CHR(10) || ',' || CHR(9)) 
					WITHIN GROUP(ORDER BY crypto_id) || CHR(10) || 
				')' || CHR(10) ||
				'SELECT ' || CHR(10) || 
				CHR(9) || LISTAGG(
					DECODE(
						is_crypted
					,	'N', source_column
					,	'Y', 'PH_CRYPTO.ENCRYPT(' || source_column || ', ' || CHR(39) || p_key_str || CHR(39) || ')'
					)
				,	CHR(10) || ',' || CHR(9)
				) WITHIN GROUP(ORDER BY crypto_id) || CHR(10) ||
				'FROM ' || CHR(10) ||
				CHR(9) || source_owner || '.' || source_table AS insert_statement
			,	DECODE(load_type, 'TRUNCATE', 'TRUNCATE TABLE ' || target_owner || '.' || targer_table, 'APPEND', 'BEGIN NULL; END;') as truncate_statement
			FROM 
				crypto_configuartion
			GROUP BY
				load_type
			,	target_owner
			,	targer_table
			,	source_owner
			,	source_table
		) LOOP
			-- EXECUTE IMMEDIATE ''
			DBMS_OUTPUT.PUT_LINE(cur.truncate_statement);
			DBMS_OUTPUT.PUT_LINE(cur.insert_statement);
		END LOOP;
	END encrypt_all;
END crypto_system;
/

show error


