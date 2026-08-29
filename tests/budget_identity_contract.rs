use workflow_verifier::internal::conformance::foundation::{
    Budget, BudgetKind, BudgetTracker, DependencyClass, GIT_SHA1_HEX_DIGITS, SHA256_HEX_DIGITS,
    classify_reference,
};

#[test]
fn every_budget_accepts_its_boundary_and_rejects_the_next_unit() {
    const SINGLE_UNIT_LIMIT: u64 = 1;
    const OVER_SINGLE_UNIT_LIMIT: u64 = SINGLE_UNIT_LIMIT + 1;

    let budget = Budget {
        max_input_bytes: SINGLE_UNIT_LIMIT,
        max_file_bytes: SINGLE_UNIT_LIMIT,
        max_snapshot_bytes: u64::MAX,
        max_entries: u64::MAX,
        max_nodes: 0,
        max_edges: 0,
        max_nesting: u32::MAX,
    };
    let mut tracker = BudgetTracker::new(budget);

    let input_at_limit = usize::try_from(SINGLE_UNIT_LIMIT).expect("test limit fits usize");
    let input_over_limit =
        usize::try_from(OVER_SINGLE_UNIT_LIMIT).expect("test attempt fits usize");
    assert!(tracker.input(input_at_limit).is_ok());
    let input_error = tracker
        .input(input_over_limit)
        .expect_err("input beyond the boundary must fail");
    assert_eq!(input_error.kind, BudgetKind::InputBytes);
    assert_eq!(input_error.limit, SINGLE_UNIT_LIMIT);
    assert_eq!(input_error.attempted, OVER_SINGLE_UNIT_LIMIT);

    assert!(tracker.file(SINGLE_UNIT_LIMIT).is_ok());
    let file_error = tracker
        .file(OVER_SINGLE_UNIT_LIMIT)
        .expect_err("file beyond the boundary must fail");
    assert_eq!(file_error.kind, BudgetKind::FileBytes);
    assert_eq!(file_error.limit, SINGLE_UNIT_LIMIT);
    assert_eq!(file_error.attempted, OVER_SINGLE_UNIT_LIMIT);

    assert_eq!(
        tracker.node().expect_err("zero node quota must fail").kind,
        BudgetKind::Nodes
    );
    assert_eq!(
        tracker.edge().expect_err("zero edge quota must fail").kind,
        BudgetKind::Edges
    );
}

#[test]
fn immutable_revision_requires_an_exact_supported_hexadecimal_width() {
    let sha1 = "a".repeat(GIT_SHA1_HEX_DIGITS);
    let sha256 = "b".repeat(SHA256_HEX_DIGITS);
    let non_hex_sha1 = "g".repeat(GIT_SHA1_HEX_DIGITS);

    assert_eq!(
        classify_reference(&format!("org/action@{sha1}")),
        DependencyClass::Immutable
    );
    assert_eq!(
        classify_reference(&format!("org/action@{sha256}")),
        DependencyClass::Immutable
    );
    assert_eq!(classify_reference("org/action@a"), DependencyClass::Mutable);
    assert_eq!(
        classify_reference(&format!("org/action@{non_hex_sha1}")),
        DependencyClass::Mutable
    );
}
