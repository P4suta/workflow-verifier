use crate::foundation::JsonValue;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Truth {
    False,
    True,
    Unknown,
}

/// A reduced ordered binary decision diagram. Branch construction and apply
/// preserve the lexical variable order, giving semantic equality independent
/// of parse or worker order.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Condition {
    False,
    True,
    Branch {
        variable: String,
        low: Box<Self>,
        high: Box<Self>,
    },
}

#[derive(Clone, Copy)]
enum Operation {
    And,
    Or,
}

impl Condition {
    #[must_use]
    fn branch(variable: String, low: Self, high: Self) -> Self {
        if low == high {
            low
        } else {
            Self::Branch {
                variable,
                low: Box::new(low),
                high: Box::new(high),
            }
        }
    }

    #[must_use]
    pub fn atom(variable: impl Into<String>) -> Self {
        Self::branch(variable.into(), Self::False, Self::True)
    }

    #[must_use]
    pub fn not(&self) -> Self {
        match self {
            Self::False => Self::True,
            Self::True => Self::False,
            Self::Branch {
                variable,
                low,
                high,
            } => Self::branch(variable.clone(), low.not(), high.not()),
        }
    }

    fn apply(operation: Operation, left: &Self, right: &Self) -> Self {
        if left == right {
            return left.clone();
        }
        match (operation, left, right) {
            (Operation::And, Self::False, _) | (Operation::And, _, Self::False) => Self::False,
            (Operation::And, Self::True, value)
            | (Operation::And, value, Self::True)
            | (Operation::Or, Self::False, value)
            | (Operation::Or, value, Self::False) => value.clone(),
            (Operation::Or, Self::True, _) | (Operation::Or, _, Self::True) => Self::True,
            (
                _,
                Self::Branch {
                    variable: left_variable,
                    low: left_low,
                    high: left_high,
                },
                Self::Branch {
                    variable: right_variable,
                    low: right_low,
                    high: right_high,
                },
            ) => match left_variable.cmp(right_variable) {
                std::cmp::Ordering::Less => Self::branch(
                    left_variable.clone(),
                    Self::apply(operation, left_low, right),
                    Self::apply(operation, left_high, right),
                ),
                std::cmp::Ordering::Greater => Self::branch(
                    right_variable.clone(),
                    Self::apply(operation, left, right_low),
                    Self::apply(operation, left, right_high),
                ),
                std::cmp::Ordering::Equal => Self::branch(
                    left_variable.clone(),
                    Self::apply(operation, left_low, right_low),
                    Self::apply(operation, left_high, right_high),
                ),
            },
        }
    }

    #[must_use]
    pub fn and(&self, other: &Self) -> Self {
        Self::apply(Operation::And, self, other)
    }

    #[must_use]
    pub fn or(&self, other: &Self) -> Self {
        Self::apply(Operation::Or, self, other)
    }

    #[must_use]
    pub fn satisfiable(&self) -> bool {
        *self != Self::False
    }

    #[must_use]
    pub fn implies(&self, conclusion: &Self) -> bool {
        !self.and(&conclusion.not()).satisfiable()
    }

    pub fn evaluate(&self, lookup: &impl Fn(&str) -> Option<bool>) -> Truth {
        match self {
            Self::False => Truth::False,
            Self::True => Truth::True,
            Self::Branch {
                variable,
                low,
                high,
            } => match lookup(variable) {
                Some(false) => low.evaluate(lookup),
                Some(true) => high.evaluate(lookup),
                None => {
                    let low = low.evaluate(lookup);
                    let high = high.evaluate(lookup);
                    if low == high { low } else { Truth::Unknown }
                }
            },
        }
    }

    #[must_use]
    pub fn atoms(&self) -> Vec<String> {
        fn collect(value: &Condition, output: &mut BTreeSet<String>) {
            if let Condition::Branch {
                variable,
                low,
                high,
            } = value
            {
                output.insert(variable.clone());
                collect(low, output);
                collect(high, output);
            }
        }
        let mut atoms = BTreeSet::new();
        collect(self, &mut atoms);
        atoms.into_iter().collect()
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        match self {
            Self::False => JsonValue::Boolean(false),
            Self::True => JsonValue::Boolean(true),
            Self::Branch {
                variable,
                low,
                high,
            } => JsonValue::Object(BTreeMap::from([
                ("high".to_owned(), high.to_json()),
                ("low".to_owned(), low.to_json()),
                ("variable".to_owned(), JsonValue::String(variable.clone())),
            ])),
        }
    }
}

impl fmt::Display for Condition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::False => formatter.write_str("false"),
            Self::True => formatter.write_str("true"),
            Self::Branch {
                variable,
                low,
                high,
            } if **low == Self::False && **high == Self::True => formatter.write_str(variable),
            Self::Branch {
                variable,
                low,
                high,
            } => {
                write!(
                    formatter,
                    "((not {variable} and {low}) or ({variable} and {high}))"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Condition;

    #[test]
    fn robdd_is_canonical() {
        let a = Condition::atom("a");
        let b = Condition::atom("b");
        assert_eq!(a.and(&b), b.and(&a));
        assert!(a.and(&b).implies(&a));
        assert!(!a.implies(&b));
        assert_eq!(a.or(&a.not()), Condition::True);
    }
}
