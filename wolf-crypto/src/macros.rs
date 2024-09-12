macro_rules! non_fips {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "allow-non-fips")]
            $item
        )*
    };
}