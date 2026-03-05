# How to contribute:
Feel free to submit a pull request (PR) after going through the below checklists.

## Testing code
Please make sure to test all of your code to the best of your ability prior to submiting a pull request this includes:
1. Rebasing to current main branch.
2. Run cargo build, cargo test
3. Run clippy --features full
4. Run cargo fmt

# Code Standards

This is a primarily rust based project, here are some requested practices for ease of development:

1. Ensure all documentation comments are work appropriate.
2. Use crate, std, external for dependencies in each file.
3. Ensure any new files created, and any code added has ample doc comments that are clear, concise and when possible reference original specifications.
4. Make sure to write tests for code added in a #\[cfg\(test\)\]
