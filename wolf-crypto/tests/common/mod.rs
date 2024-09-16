#[macro_use]
pub mod parse;
pub mod mct;
pub mod load;
pub mod trusted_url;

macro_rules! make_mc_test {
    ($files:ident with sz: $sz:literal, hasher: $hasher:ty, cases: $max:literal) => {{
        let test = *$files.iter().find(|(name, _)| $crate::common::mct::is_monte(*name))
            .unwrap();
        let bytes = fs::read(test.1).unwrap();

        let mut seed = [0u8; $sz];
        let (init_seed, mut test) = $crate::common::mct::MonteTest::new(bytes.as_slice()).start();
        hex::decode_to_slice(init_seed, seed.as_mut_slice()).unwrap();

        let mut hasher = <$hasher>::new().unwrap();

        for j in 0..$max {
            let mut md = [0u8; $sz];

            for i in 0..1000 {
                if i == 0 {
                    hasher.try_update(&seed).unwrap();
                } else {
                    hasher.try_update(&md).unwrap();
                }
                md = hasher.try_finalize().unwrap();
            }

            // Compare with expected value from test vector
            if let Some((count, expected)) = test.next_item_sized::<{ $sz }>() {
                let count = core::str::from_utf8(count).unwrap();
                assert_eq!(
                    md, expected,
                    "Failed at count {} with seed: {}",
                    count, hex::encode(&seed)
                );
                assert_eq!(count, format!("{j}").as_str());
            } else {
                panic!("Ran out of test vector data at iter: {j}");
            }

            seed = md;
        }

        assert!(
            test.next_item_sized::<{ $sz }>().is_none(), "Not all cases were covered"
        );
    }};
}