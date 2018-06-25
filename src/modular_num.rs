/// Defines a macro to define a modular number that uses a predefined number of bits

#[macro_export]
macro_rules! modular_num {
	(pub $x:ident($type:ident, $num:expr)) => {
		modular_num_impls!($x, $type, $num);

		pub use self::mod_num_impl::$x;
	};
	($x:ident($type:ident, $num:expr)) => {
		modular_num_impls!($x, $type, $num);

		use self::mod_num_impl::$x;
	};
}

macro_rules! modular_num_impls {
	($x:ident, $type:ident, $num:expr) => {

		mod mod_num_impl {

			use std::{fmt, cmp::Ordering, ops::{Add, Rem, Sub, AddAssign}};
			use rand::{distributions::{Distribution, Standard}, Rng};

			#[derive(Eq, PartialEq, Clone, Copy, Debug)]
			pub struct $x(pub $type);

			impl $x {
				pub const MAX: $type = 1 << $num;
				pub const MAX_DIFF: $type = 1 << ($num - 1);

				pub fn new(from: $type) -> $x { $x(from % $x::MAX) }

				pub fn as_raw(&self) -> $type { self.0 }
			}

			impl Distribution<$x> for Standard {
				fn sample<T: Rng + ?Sized>(&self, rng: &mut T) -> $x {
					$x::new(rng.gen::<$type>())
				}
			}

			impl Add<$type> for $x {
				type Output = Self;

				fn add(self, other: $type) -> Self {
					let added = $type::wrapping_add(self.0, other);

					$x(added % $x::MAX)
				}
			}

			/// Move a sequence number backwards by an offset
			/// ie: SeqNumber(3) - 2 == 1
			/// and SeqNumber(0) - 1 == SeqNumber(MAX)
			impl Sub<$type> for $x {
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
			impl Sub<$x> for $x {
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
			impl Ord for $x {
				fn cmp(&self, other: &Self) -> Ordering {
					let diff = *self - *other;

					if diff == 0 {
						return Ordering::Equal;
					}

					if diff < $x::MAX_DIFF {
						// this means self was bigger than other
						Ordering::Greater
					} else {
						// this means other was greater
						Ordering::Less
					}
				}
			}

			impl Rem<$type> for $x {
				type Output = $type;

				fn rem(self, other: $type) -> Self::Output {
					self.0 % other
				}
			}

			impl PartialOrd for $x {
				fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
					Some(self.cmp(other))
				}
			}

			impl AddAssign<$type> for $x {
				fn add_assign(&mut self, rhs: $type) {
					*self = *self + rhs
				}
			}

			impl fmt::Display for $x {
				fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
					write!(f, "{}", self.0)
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {

	use std::cmp::Ordering;

	modular_num! { SeqNumber(u32, 31) }

	#[test]
	fn new() {
		// shouldn't be truncated, first bit is zero
		assert_eq!(SeqNumber::new(1687761238).as_raw(), 1687761238);
		assert_eq!(SeqNumber::new(1687761239 | 1 << 31).as_raw(), 1687761239);
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

		assert_eq!(SeqNumber(812827).cmp(&SeqNumber(812827)), Ordering::Equal);
		assert_eq!(SeqNumber(812827), SeqNumber(812827));
	}

}
