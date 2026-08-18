#[test]
fn type_level_security_misuse_does_not_compile() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
