macro_rules! non_fips {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "allow-non-fips")]
            $item
        )*
    };
}

macro_rules! hidden {
    ($($item:item)*) => {
        $(
            #[doc(hidden)]
            $item
        )*
    };
}

macro_rules! std {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "std")]
            $item
        )*
    };
}