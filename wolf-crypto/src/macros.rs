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
            #[cfg(feature = "alloc")]
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
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($struct), "<", $(stringify!($param)),*, ">"))
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