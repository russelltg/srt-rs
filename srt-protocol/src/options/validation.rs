use std::ops::Deref;

pub trait Validation: Sized {
    type Error;

    fn is_valid(&self) -> Result<(), Self::Error>;

    fn try_validate(self) -> Result<Valid<Self>, Self::Error> {
        self.is_valid()?;
        Ok(Valid(self))
    }
}

pub trait CompositeValidation: Validation {
    fn is_valid_composite(&self) -> Result<(), <Self as Validation>::Error>;
}

pub trait OptionsOf<C>: CompositeValidation {
    fn set_options(&mut self, value: C);
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct Valid<T: Validation>(T);

impl<T: Validation> Deref for Valid<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Validation> Valid<T> {
    pub fn into_value(self) -> T {
        self.0
    }
    pub fn set(self, set_fn: impl FnOnce(&mut T)) -> Result<Self, <T as Validation>::Error> {
        let mut inner = self.0;
        set_fn(&mut inner);
        inner.try_validate()
    }

    pub fn with<F>(self, options: F) -> Result<Self, <T as Validation>::Error>
    where
        T: OptionsOf<F>,
        F: Validation<Error = <T as Validation>::Error>,
    {
        let mut inner = self.0;
        inner.set_options(options.try_validate()?.0);
        inner.is_valid_composite()?;
        Ok(Self(inner))
    }

    pub fn with2<F1, F2>(self, options1: F1, options2: F2) -> Result<Self, <T as Validation>::Error>
    where
        T: OptionsOf<F1> + OptionsOf<F2>,
        F1: Validation<Error = <T as Validation>::Error>,
        F2: Validation<Error = <T as Validation>::Error>,
    {
        let mut inner = self.0;
        inner.set_options(options1.try_validate()?.0);
        inner.set_options(options2.try_validate()?.0);
        inner.is_valid_composite()?;
        Ok(Self(inner))
    }

    pub fn with3<F1, F2, F3>(
        self,
        options1: F1,
        options2: F2,
        options3: F3,
    ) -> Result<Self, <T as Validation>::Error>
    where
        T: OptionsOf<F1> + OptionsOf<F2> + OptionsOf<F3>,
        F1: Validation<Error = <T as Validation>::Error>,
        F2: Validation<Error = <T as Validation>::Error>,
        F3: Validation<Error = <T as Validation>::Error>,
    {
        let mut inner = self.0;
        inner.set_options(options1.try_validate()?.0);
        inner.set_options(options2.try_validate()?.0);
        inner.set_options(options3.try_validate()?.0);
        inner.is_valid_composite()?;
        Ok(Self(inner))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    struct Test {
        pub field: u32,
    }

    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    struct Test2 {
        pub field: u32,
    }

    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    struct Test3 {
        pub field: u32,
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    enum TestError {
        Test(Test),
        Test2(Test2),
        Test3(Test3),
        TestParent(TestParent),
    }

    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    struct TestParent {
        pub child: Test,
        pub child2: Test2,
        pub child3: Test3,
    }

    impl OptionsOf<Test> for TestParent {
        fn set_options(&mut self, value: Test) {
            self.child = value;
        }
    }

    impl OptionsOf<Test2> for TestParent {
        fn set_options(&mut self, value: Test2) {
            self.child2 = value;
        }
    }

    impl OptionsOf<Test3> for TestParent {
        fn set_options(&mut self, value: Test3) {
            self.child3 = value;
        }
    }

    impl Validation for Test {
        type Error = TestError;

        fn is_valid(&self) -> Result<(), Self::Error> {
            if self.field > 10 {
                Ok(())
            } else {
                Err(TestError::Test(self.clone()))
            }
        }
    }

    impl Validation for Test2 {
        type Error = TestError;

        fn is_valid(&self) -> Result<(), Self::Error> {
            if self.field > 20 {
                Ok(())
            } else {
                Err(TestError::Test2(self.clone()))
            }
        }
    }

    impl Validation for Test3 {
        type Error = TestError;

        fn is_valid(&self) -> Result<(), Self::Error> {
            if self.field > 20 {
                Ok(())
            } else {
                Err(TestError::Test3(self.clone()))
            }
        }
    }

    impl CompositeValidation for TestParent {
        fn is_valid_composite(&self) -> Result<(), Self::Error> {
            if self.child.field == self.child2.field {
                Ok(())
            } else {
                Err(TestError::TestParent(self.clone()))
            }
        }
    }

    impl Validation for TestParent {
        type Error = TestError;

        fn is_valid(&self) -> Result<(), Self::Error> {
            self.child.is_valid()?;
            self.child2.is_valid()?;
            self.child3.is_valid()?;
            self.is_valid_composite()
        }
    }

    struct TestBuilder(Valid<TestParent>);
    impl TestBuilder {
        pub fn new() -> Self {
            Self(Default::default())
        }

        pub fn with<F>(mut self, options: F) -> Result<Self, <TestParent as Validation>::Error>
        where
            TestParent: OptionsOf<F>,
            F: Validation<Error = <TestParent as Validation>::Error>,
        {
            self.0 = self.0.with(options)?;
            Ok(self)
        }

        pub fn build(self) -> Valid<TestParent> {
            self.0
        }
    }

    #[test]
    fn test_validation() {
        let test = Test { field: 40 };
        let test2 = Test2 { field: 40 };
        let test3 = Test3 { field: 40 };
        let parent: Valid<TestParent> = TestParent {
            child: Test { field: 30 },
            child2: Test2 { field: 30 },
            child3: Test3 { field: 30 },
        }
        .try_validate()
        .unwrap();

        let parent = parent.with2(test.clone(), test2.clone()).unwrap();

        let parent = parent.with3(test.clone(), test2, test3).unwrap();

        assert_eq!(
            parent.child.field, test.field,
            "{} != {}",
            parent.child.field, test.field
        );

        let fail = parent.with(Test { field: 1234 });
        assert_eq!(
            fail,
            Err(TestError::TestParent(TestParent {
                child: Test { field: 1234 },
                child2: Test2 { field: 40 },
                child3: Test3 { field: 30 }
            }))
        );

        let parent = TestBuilder::new()
            .with(Test { field: 0 })
            .unwrap()
            .with(Test2 { field: 0 })
            .unwrap()
            .build();
        assert_eq!(
            parent.child.field, test.field,
            "{} != {}",
            parent.child.field, test.field
        );
    }
}
