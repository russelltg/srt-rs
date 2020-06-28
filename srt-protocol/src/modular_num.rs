/// Defines a macro to define a modular number that uses a predefined number of bits
use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub struct OutOfRangeError(pub &'static str);

impl Display for OutOfRangeError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "Number out of range for `{}`", self.0)
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! modular_num {
    (pub $x:ident($type:ident, $num:expr)) => {
        $crate::modular_num_impls!((pub), $x, $type, $num);
    };
    ($x:ident($type:ident, $num:expr)) => {
        $crate::modular_num_impls!((), $x, $type, $num);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! modular_num_impls {
    (($($publicity:tt)*), $x:ident, $type:ident, $num:expr) => {

        #[derive(Eq, PartialEq, Clone, Copy, Debug)]
        $($publicity)* struct $x(pub $type);

        impl $x {
            pub const MAX: $type = 1 << $num;
            pub const MAX_DIFF: $type = 1 << ($num - 1);

            pub fn new_truncate(from: $type) -> $x {
                $x(from % $x::MAX)
            }
            pub fn new(from: $type) -> Result<$x, $crate::modular_num::OutOfRangeError> {
                if from > $x::MAX {
                    Err($crate::modular_num::OutOfRangeError(stringify!($x)))
                } else {
                    Ok($x(from))
                }
            }

            pub fn as_raw(&self) -> $type {
                self.0
            }
        }

        impl ::std::convert::TryFrom<$type> for $x {
            type Error = $crate::modular_num::OutOfRangeError;

            fn try_from(from: $type) -> Result<Self, Self::Error> {
                $x::new(from)
            }
        }

        impl ::rand::distributions::Distribution<$x> for ::rand::distributions::Standard {
            fn sample<T: ::rand::Rng + ?Sized>(&self, rng: &mut T) -> $x {
                $x::new_truncate(rng.gen::<$type>())
            }
        }

        #[allow(clippy::suspicious_arithmetic_impl)]
        impl ::std::ops::Add<$type> for $x {
            type Output = Self;

            fn add(self, other: $type) -> Self {
                let added = $type::wrapping_add(self.0, other);

                $x(added % $x::MAX)
            }
        }

        /// Move a sequence number backwards by an offset
        /// ie: SeqNumber(3) - 2 == 1
        /// and SeqNumber(0) - 1 == SeqNumber(MAX)
        impl ::std::ops::Sub<$type> for $x {
            type Output = Self;

            fn sub(self, other: $type) -> Self {
                if self.0 < other {
                    // wrap
                    $x($x::MAX - (other - self.0))
                } else {
                    $x(self.0 - other)
                }
            }
        }

        /// Gets the distance between two sequence numbers
        /// Always measured with first one first and the second one second
        /// ie: SeqNumber(0) - SeqNumber(MAX) == 1
        /// and SeqNumber(1) - SeqNumber(0) == 1
        impl ::std::ops::Sub<$x> for $x {
            type Output = $type;

            fn sub(self, other: Self) -> Self::Output {
                if self.0 >= other.0 {
                    // no wrap required
                    self.0 - other.0
                } else {
                    $x::MAX - (other.0 - self.0)
                }
            }
        }

        /// Ordering sequence numbers is difficult, as they are modular
        /// How it works is if the absolute value of the difference between sequence numbers is greater than
        /// MAX_DIFF, then wrapping is assumed
        impl ::std::cmp::Ord for $x {
            fn cmp(&self, other: &Self) -> ::std::cmp::Ordering {
                let diff = *self - *other;

                if diff == 0 {
                    return ::std::cmp::Ordering::Equal;
                }

                if diff < $x::MAX_DIFF {
                    // this means self was bigger than other
                    ::std::cmp::Ordering::Greater
                } else {
                    // this means other was greater
                    ::std::cmp::Ordering::Less
                }
            }
        }

        impl ::std::ops::Rem<$type> for $x {
            type Output = $type;

            fn rem(self, other: $type) -> Self::Output {
                self.0 % other
            }
        }

        impl ::std::cmp::PartialOrd for $x {
            fn partial_cmp(&self, other: &Self) -> Option<::std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl ::std::ops::AddAssign<$type> for $x {
            fn add_assign(&mut self, rhs: $type) {
                *self = *self + rhs
            }
        }

        impl ::std::fmt::Display for $x {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

#[cfg(test)]
mod tests {

    use std::cmp::Ordering;

    modular_num! { SeqNumber(u32, 31) }

    #[test]
    fn new() {
        // shouldn't be truncated, first bit is zero
        assert_eq!(
            SeqNumber::new(1_687_761_238).unwrap().as_raw(),
            1_687_761_238
        );
        assert!(SeqNumber::new(1_687_761_239 | 1 << 31).is_err());
    }

    #[test]
    fn max() {
        assert_eq!(SeqNumber::MAX, 1 << 31);
        assert_eq!(SeqNumber::MAX_DIFF, 1 << 30);
    }

    #[test]
    fn mod_num_addition() {
        assert_eq!(SeqNumber(14), SeqNumber(5) + 9);
        assert_eq!(SeqNumber(SeqNumber::MAX - 1) + 4, SeqNumber(3));
    }

    #[test]
    fn mod_num_subtraction() {
        assert_eq!(
            SeqNumber(SeqNumber::MAX - 10) - (SeqNumber::MAX - 50),
            SeqNumber(40)
        );
        assert_eq!(SeqNumber(4) - 10, SeqNumber(SeqNumber::MAX - 6));
        assert_eq!(SeqNumber(5) - SeqNumber(1), 4);
        assert_eq!(SeqNumber(2) - SeqNumber(SeqNumber::MAX - 1), 3);
        assert_eq!(SeqNumber(5) - SeqNumber(5), 0);
    }

    #[test]
    fn mod_num_cmp() {
        assert_eq!(SeqNumber(3), SeqNumber(3));
        assert!(SeqNumber(3) < SeqNumber(4));
        assert!(SeqNumber(13) > SeqNumber(5));

        assert_eq!(SeqNumber(812_827).cmp(&SeqNumber(812_827)), Ordering::Equal);
        assert_eq!(SeqNumber(812_827), SeqNumber(812_827));
    }
}
