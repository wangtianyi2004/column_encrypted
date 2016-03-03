-- crypto test case


CREATE TABLE crypto_log (
	table_name		VARCHAR2(50)
,	column_name		VARCHAR2(50)
,	crypto_type		VARCHAR2(10)
,	crypto_status	VARCHAR2(10)
);	



drop table crypto_configuartion;
create table crypto_configuartion(
	crypto_id		NUMBER
,	source_owner	varchar2(30)
,	source_table	varchar2(30)
,	source_column	varchar2(30)
,	target_owner	varchar2(30)
,	targer_table	varchar2(30)
,	target_column	varchar2(30)
,	is_crypted		char(1)
,	load_type		varchar2(20)
);

create table crypto_log(
	table_name		varchar2(50)
,	column_name		varchar2(50)
,	crypto_type		varchar2(10)
,	crypto_status	varchar2(10)
);	


drop table original_tab;
create table original_tab(
	original_id 	number
,	original_name 	varchar2(1000)
,	original_dt		date
,	original_c1		number
,	original_c2		varchar2(50)
);


drop table encrypted_tab;
create table encrypted_tab(
	encrypted_id 	raw(2000)
,	encrypted_name 	raw(2000)
,	encrypted_dt 	raw(2000)
,	encrypted_c1	number
,	encrypted_c2	varchar2(50)			
);


drop table dencrypted_tab;
create table dencrypted_tab(
	dencrypted_id 	number
,	dencrypted_name varchar2(1000)
,	dencrypted_dt 	date
,	dencrypted_c1		number
,	dencrypted_c2		varchar2(50)
);


truncate table original_tab;
insert into original_tab(original_id, original_name, original_dt, original_c1, original_c2) values(1, 'abc123大连250μg：0.5ml+-*@as', sysdate, 20, 'Masd');
insert into original_tab(original_id, original_name, original_dt, original_c1, original_c2) values(2, 'aga%23大山大路附近25μg：0.2834uia.'';+-*@as', sysdate + 10, 39, '都发过了健康');
insert into original_tab(original_id, original_name, original_dt, original_c1, original_c2) values(3, 'aga%23大山大路附近"’“@as', sysdate - 782.8234, 23, '^*()(');


truncate table crypto_configuartion;
insert into crypto_configuartion values (1, 'WTY','ORIGINAL_TAB','ORIGINAL_ID',  'WTY', 'ENCRYPTED_TAB', 'ENCRYPTED_ID',  'Y', 'APPEND');
insert into crypto_configuartion values (2, 'WTY','ORIGINAL_TAB','ORIGINAL_NAME','WTY', 'ENCRYPTED_TAB', 'ENCRYPTED_NAME','Y', 'APPEND');
insert into crypto_configuartion values (3, 'WTY','ORIGINAL_TAB','ORIGINAL_DT',  'WTY', 'ENCRYPTED_TAB', 'ENCRYPTED_DT',  'Y', 'APPEND');
insert into crypto_configuartion values (4, 'WTY','ORIGINAL_TAB','ORIGINAL_C1',  'WTY', 'ENCRYPTED_TAB', 'ENCRYPTED_C1',  'N', 'APPEND');
insert into crypto_configuartion values (5, 'WTY','ORIGINAL_TAB','ORIGINAL_C2',  'WTY', 'ENCRYPTED_TAB', 'ENCRYPTED_C2',  'N', 'APPEND');

commit;





