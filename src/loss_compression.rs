use std::iter::Iterator;

/// Iterator for compressing loss lists
pub struct CompressLossList<I> {
    /// Underlying iterator
    iterator: I,

    /// The next item
    next: Option<i32>,

    /// True if looping
    looping: bool,
    last_in_loop: i32,
}

impl<I> Iterator for CompressLossList<I>
where I: Iterator<Item = i32> {
    type Item = i32;

    fn next(&mut self) -> Option<i32> {
        // if we're at the start, assign a next
        if self.next.is_none() {
            self.next = Some(self.iterator.next()?);
        }

        loop {

            // The state right here is
            // neither this nor next have been returned, and we need to figure out if this is
            // a) already in a loop and we continue on with that loop
            // b) already in a loop and need to break out
            // c) not in a loop and need to start one
            // d) not in a loop and doesn't need to start one


            let this = self.next.unwrap();
            self.next = match self.iterator.next() {
                Some(i) => Some(i),
                None => {
                    // invalidate next, so it None will be returned next time
                    self.next = None;

                    // return the one we have
                    return Some(this);
                }
            };

            // the list must be sorted
            assert!(this < self.next.unwrap());

            if self.looping && self.last_in_loop + 2 == self.next.unwrap() {
                // continue with the loop
                self.last_in_loop += 1;

                continue;
            } else if self.looping {
                // break out of the loop
                self.looping = false;

                return Some(this);
            } else if this + 1 == self.next.unwrap() {
                // create a loop
                self.looping = true;
                self.last_in_loop = this;

                // set the first bit to 1
                return Some(this | 1 << 31);
            } else {
                // no looping necessary
                return Some(this);
            }

        }
    }
}

// keep in mind loss_list must be sorted
// takes in a list of i32, which is the loss list
pub fn compress_loss_list<I>(mut loss_list: I) -> CompressLossList<I>
    where
        I: Iterator<Item = i32>,
{
    CompressLossList {
        iterator: loss_list,
        next: None,
        looping: false,
        last_in_loop: 0
    }
}

pub struct DecompressLossList<I> {
    iterator: I,

    loop_next_end: Option<(i32, i32)>,
}

impl<I: Iterator<Item = i32>> Iterator for DecompressLossList<I> {
    type Item = i32;

    fn next(&mut self) -> Option<i32> {
        match self.loop_next_end {
            Some((next, end)) if next == end => {
                // loop is over
                self.loop_next_end = None;

                Some(next)
            },
            Some((next, end)) => {
                // continue the loop
                self.loop_next_end = Some((next + 1, end));

                Some(next)
            },
            None => {
                // no current loop
                let next = self.iterator.next()?;

                // is this a loop start
                if next & (1<<31) != 0 {
                    // set the first bit to zero
                    let next_num = next << 1 >> 1;
                    self.loop_next_end = Some((next_num + 1, match self.iterator.next() {
                        Some(i) => i,
                        None => panic!("unterminated loop while decompressing loss list"),
                    }));

                    Some(next_num)
                } else {
                    // no looping is possible
                    Some(next)
                }
            }
        }
    }
}

pub fn decompress_loss_list<I: Iterator<Item=i32>>(loss_list: I) -> DecompressLossList<I> {
    DecompressLossList {
        iterator: loss_list,
        loop_next_end: None,
    }
}

#[test]
fn tests() {

    macro_rules! test_comp_decomp {
        ($x:expr, $y:expr) => {{
            assert_eq!(
                compress_loss_list($x.iter().cloned()).collect::<Vec<_>>(),
                $y.iter().cloned().collect::<Vec<_>>()
            );
            assert_eq!(
                decompress_loss_list($y.iter().cloned()).collect::<Vec<_>>(),
                $x.iter().cloned().collect::<Vec<_>>()
            );
        }}
    }
    let one = 1 << 31;

    test_comp_decomp!([13, 14, 15, 16, 17, 18, 19], [13 | one, 19]);

    test_comp_decomp!([1, 2, 3, 4, 5, 9, 11, 12, 13, 16, 17],
        [1 | 1 << 31, 5, 9, 11 | 1 << 31, 13, 16 | 1 << 31, 17]);
}
