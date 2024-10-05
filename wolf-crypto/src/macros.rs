macro_rules! non_fips {
    ($($item:item)*) => {
        $(
            #[cfg_attr(docsrs, doc(cfg(feature = "allow-non-fips")))]
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
            #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
            #[cfg(feature = "std")]
            $item
        )*
    };
}

macro_rules! alloc {
    ($($item:item)*) => {
        $(
            #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
            #[cfg(any(feature = "alloc", test))]
            $item
        )*
    };
}

macro_rules! panic_api {
    ($($item:item)*) => {
        $(
            #[cfg_attr(docsrs, doc(cfg(feature = "can-panic")))]
            #[cfg(feature = "can-panic")]
            $item
        )*
    };
}

macro_rules! no_std_io {
    ($($item:item)*) => {
        $(
            #[cfg_attr(docsrs, doc(cfg(feature = "embedded-io")))]
            #[cfg(feature = "embedded-io")]
            $item
        )*
    }
}

macro_rules! io_impls {
    ($($item:item)*) => {
        $(
            #[cfg_attr(docsrs, doc(cfg(any(feature = "std", feature = "embedded-io"))))]
            #[cfg(any(feature = "std", feature = "embedded-io"))]
            $item
        )*
    };
}

macro_rules! opaque_dbg {
    ($struct:ident $(<$lt:lifetime>)?) => {
        impl $(<$lt>)? ::core::fmt::Debug for $struct $(<$lt>)? {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(concat!(stringify!($struct), "{{ ... }}"))
            }
        }
    };
    ($struct:ident <$($param:ident),*>) => {
        impl ::core::fmt::Debug for $struct <$($param),*> {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Formatter::write_str(
                    f,
                    concat!(stringify!($struct), "<", $(stringify!($param)),*, ">")
                )
            }
        }
    }
}

macro_rules! into_result {
    ($res:expr, ok => $ok:expr, err => $err:expr) => {
        if $res.is_ok() {
            Ok($ok)
        } else {
            Err($err)
        }
    };
}

macro_rules! define_state {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        $(#[$meta])*
        pub struct $name;

        impl $crate::sealed::Sealed for $name {}
        impl State for $name {}
    };

    ($(
        $(#[$meta:meta])*
        $name:ident
    ),* $(,)?) => {
        $(
            define_state! {
                $(#[$meta])*
                $name
            }
        )*
    };
}

macro_rules! arb_key {
    (struct $ident:ident :: $construct:ident ([u8; $sz:literal])) => {
        #[cfg(test)]
        impl ::proptest::arbitrary::Arbitrary for $ident {
            type Parameters = ();

            fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
                use ::proptest::strategy::Strategy as _;
                ::proptest::prelude::any::<[u8; $sz]>().prop_map(Self::$construct).boxed()
            }

            type Strategy = ::proptest::strategy::BoxedStrategy<Self>;
        }

        #[cfg(kani)]
        impl ::kani::Arbitrary for $ident {
            fn any() -> Self {
                Self::$construct(::kani::any())
            }
        }
    };
    (enum $ident:ident {
        $(
            $variant:ident ([u8; $sz:literal])
        ),*
        $(,)?
    }) => {
        #[cfg(test)]
        impl ::proptest::arbitrary::Arbitrary for $ident {
            type Parameters = ();

            fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
                use ::proptest::strategy::Strategy as _;

                ::proptest::prop_oneof![
                    $(::proptest::prelude::any::<[u8; $sz]>().prop_map(Self::$variant)),*
                ].boxed()
            }

            type Strategy = ::proptest::strategy::BoxedStrategy<Self>;
        }
    }
}