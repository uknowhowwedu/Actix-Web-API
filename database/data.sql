INSERT INTO main.users (id, username, acc_type, password, salt, creation_date) VALUES (gen_random_uuid(), 'admin', 'a', '1871041294411945551462421031041692742173111630138205127219151891271375920614121717919220682252217129217312838101282017019424512397632491271371271255824821622874212155', '0o2V4ANF8d5xkeIog215Xg', EXTRACT(EPOCH FROM NOW())::integer) ON CONFLICT (username) DO NOTHING;
INSERT INTO main.data SELECT id FROM main.users WHERE username = 'admin' ON CONFLICT (id) DO NOTHING;
--Default API admin password: Ihfs&^86f8hs__98987
--Adheres to hashing configuration in config.rs