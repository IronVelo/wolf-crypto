#[macro_use]
pub mod parse;
pub mod mct;
pub mod load;
pub mod trusted_url;
pub mod files;

macro_rules! make_mc_test {
    ($files:ident with sz: $sz:literal, hasher: $hasher:ty, cases: $max:literal) => {{
        let test = *$files.iter().find(|(name, _)| $crate::common::mct::is_monte(*name))
            .unwrap();
        let bytes = std::fs::read(test.1).unwrap();

        let mut seed = [0u8; $sz];
        let (init_seed, mut test) = $crate::common::mct::MonteTest::new(bytes.as_slice()).start();
        hex::decode_to_slice(init_seed, seed.as_mut_slice()).unwrap();

        let mut hasher = <$hasher>::new().unwrap();

        for j in 0..$max {
            for _i in 0..1000 {
                hasher.try_update(&seed).unwrap();
                seed = hasher.try_finalize().unwrap();
            }

            // Compare with expected value from test vector
            if let Some((count, expected)) = test.next_item_sized::<{ $sz }>() {
                assert_eq!(
                    seed, expected,
                    "Failed at count {} with seed: {}",
                    core::str::from_utf8(count).unwrap(), hex::encode(&seed)
                );
            } else {
                panic!("Ran out of test vector data at iter: {j}");
            }
        }

        assert!(test.next_item_sized::<{ $sz }>().is_none(), "Not all cases were covered");
    }};
}

#[inline]
pub unsafe fn swap_hash_digests_32<const LEN_32: usize>(a: *mut u8, b: *mut u8) {
    unsafe {
        let mut ptr1 = a as *mut u32;
        let mut ptr2 = b as *mut u32;

        for _ in 0..LEN_32 {
            *ptr1 ^= *ptr2;
            *ptr2 ^= *ptr1;
            *ptr1 ^= *ptr2;
            ptr1 = ptr1.add(1);
            ptr2 = ptr2.add(1);
        }
    }
}

#[inline]
pub unsafe fn swap_hash_digests_64<const LEN_64: usize>(a: *mut u8, b: *mut u8) {
    unsafe {
        let mut ptr1 = a as *mut u64;
        let mut ptr2 = b as *mut u64;

        for _ in 0..LEN_64 {
            *ptr1 ^= *ptr2;
            *ptr2 ^= *ptr1;
            *ptr1 ^= *ptr2;
            ptr1 = ptr1.add(1);
            ptr2 = ptr2.add(1);
        }
    }
}

macro_rules! make_md_mct {
    ($files:ident with sz: $sz:literal, hasher: $hasher:ty $(, align_64: $a_64:ident)? $(,)?) => {{
        make_md_mct!(@assert $($a_64, )? $sz);

        let test = *$files.iter().find(|(name, _)| $crate::common::mct::is_monte(*name))
            .unwrap();
        let bytes = std::fs::read(test.1).unwrap();

        let mut seed = [0u8; $sz];

        let (init_seed, mut test) = $crate::common::mct::MonteTest::new(bytes.as_slice()).start();
        hex::decode_to_slice(init_seed, seed.as_mut_slice()).unwrap();

        let mut hasher = <$hasher>::new().unwrap();
        let mut buffer = [0u8; $sz * 3];

        let md0_ptr = buffer.as_mut_ptr();
        let md1_ptr = unsafe { buffer.as_mut_ptr().add($sz) };
        let md2_ptr = unsafe { buffer.as_mut_ptr().add($sz * 2) };

        for _j in 0..100 {
            // Our seed is md0 -- FROM SHAVS:
            // MD0 = MD1 = MD2 = Seed;
            buffer[0..$sz].copy_from_slice(&seed);
            buffer[$sz..$sz * 2].copy_from_slice(&seed);
            buffer[$sz * 2..$sz * 3].copy_from_slice(&seed);

            for _i in 0..1000 {
                // This is the same as this from SHAVS:
                // Mi = MDi-3 || MDi-2 || MDi-1;
                // MDi = SHA(Mi);
                hasher.try_update(&buffer).unwrap();
                let new_md = hasher.finalize();
                unsafe {
                    make_md_mct!(@swap $($a_64, )? $sz)(md0_ptr, md1_ptr);
                    make_md_mct!(@swap $($a_64, )? $sz)(md1_ptr, md2_ptr);
                    core::ptr::copy_nonoverlapping(new_md.as_ptr(), md2_ptr, $sz);
                }
            }

            // Again, same as SHAVS
            // MDj = Seed = MD1002;
            unsafe { core::ptr::copy_nonoverlapping(md2_ptr, seed.as_mut_ptr(), $sz); }

            // Our seed should be equivalent as the MD for this COUNT
            let (count, expected) = test.next_item_sized::<{ $sz }>().unwrap();
            let count = core::str::from_utf8(count).unwrap(); // See I'm not doing that much unsafe.

            assert_eq!(
                seed.as_slice(), expected.as_slice(),
                "Failed at count {} with seed: {}",
                count, hex::encode(&seed)
            );
        }

        assert!(test.next_item_sized::<{ $sz }>().is_none(), "Not all cases were covered");
    }};

    (@assert true, $sz:literal) => {
        assert_eq!($sz & 7, 0)
    };
    (@assert $sz:literal) => {
        assert_eq!($sz & 3, 0)
    };

    (@swap $sz:literal) => {
        $crate::common::swap_hash_digests_32::<{$sz / 4}>
    };

    (@swap true, $sz:literal) => {
        $crate::common::swap_hash_digests_64::<{$sz / 8}>
    };
}