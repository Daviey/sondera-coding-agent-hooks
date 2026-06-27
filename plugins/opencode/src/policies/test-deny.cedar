@id("forbid-sondera-test-deny")
@description("Test policy: denies echo sondera-deny-test for integration test validation")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*sondera-deny-test*"
};
