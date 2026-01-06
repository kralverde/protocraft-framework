use crate::{from_reader_helper, to_writer_helper, traits::Serializable};

macro_rules! tuple_impls {
    ( $helper_type:ident $( $name:ident )+ ) => {
        impl<$($name: Serializable),+> Serializable for ($($name,)+) {
            fn size(&self) -> usize {
                #[allow(non_snake_case)]
                let ($($name,)+) = self;
                $(<$name as Serializable>::size($name) +)+ 0
            }
        }

        type $helper_type<$($name),+> = ($($name,)+);
        from_reader_helper!($helper_type<$($name),+>, wrapped <$($name),+> {
        $(
            #[allow(non_snake_case)]
            let $name = read!($name);
        )+
            Ok(($($name,)+))
        });

        to_writer_helper!($helper_type<$($name),+>, wrapped <$($name),+>, (this){
            #[allow(non_snake_case)]
            let ($($name,)+) = this;
        $(
            write!($name, $name);
        )+
            Ok(())
        });
    };
}

tuple_impls!(One T1);
tuple_impls!(Two T1 T2);
tuple_impls!(Three T1 T2 T3);
tuple_impls!(Four T1 T2 T3 T4);
tuple_impls!(Five T1 T2 T3 T4 T5);
tuple_impls!(Six T1 T2 T3 T4 T5 T6);
tuple_impls!(Seven T1 T2 T3 T4 T5 T6 T7);
tuple_impls!(Eight T1 T2 T3 T4 T5 T6 T7 T8);
tuple_impls!(Nine T1 T2 T3 T4 T5 T6 T7 T8 T9);
tuple_impls!(Ten T1 T2 T3 T4 T5 T6 T7 T8 T9 T10);
tuple_impls!(Eleven T1 T2 T3 T4 T5 T6 T7 T8 T9 T10 T11);
tuple_impls!(Twelve T1 T2 T3 T4 T5 T6 T7 T8 T9 T10 T11 T12);
