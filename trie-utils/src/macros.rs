#[macro_export]
macro_rules! encode {
    ($out:ident, $e:expr) => {
        $e.encode($out);
        #[cfg(feature = "debug")]
        {
            let mut vec = vec![];
            $e.encode(&mut vec);
            println!("{}: {:?}", stringify!($e), vec);
        }

    };
    ($out:ident, $e:expr, $($others:expr),+) => {
        {
            encode!($out, $e);
            encode!($out, $($others),+);
        }
    };
}
