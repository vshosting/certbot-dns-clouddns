# Contributor's Guide
First of all, thank you for contributing to certbot-dns-clouddns!

This document provides guidelines for contributing to the project. They are written to ensure its consistency and maintainability. All contributions are welcome, as long as you follow these guidelines. If you have any questions, please [create an issue](https://github.com/vshosting/certbot-dns-clouddns/issues/new).

## How to Report Bugs
Bug reports are hugely important, but please make sure to avoid duplicate reports. Before you submit one, please check [certbot-dns-clouddns issues](https://github.com/vshosting/certbot-dns-clouddns/issues), **both open and closed**, and make sure that the bug has not been reported before.

When filing an issue, include answers to the following five questions:
1. What version of certbot-dns-clouddns are you using?
2. What operating system and Python version are you using?
3. What did you do?
4. What was the expected result?
5. What was the actual result?

## Contributing Code
If this is your first time contributing code on Github, take a look at Github's [How to create a pull request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request). After you read it, you follow this checklist to make a pull request:
1. Fork the repository.
2. Setup development environment using `poetry install`.
3. Install pre-commit hooks using `poetry run pre-commit install`.
4. Run the tests using `poetry run pytest` to make sure they pass on your system.
5. Write tests for the code you are changing. It should fail.
6. Change to the code.
7. Run the test suite again, ensuring all tests, including the ones you have written, pass.
8. Make a pull request on Github.

### Code Style
- certbot-dns-clouddns adheres to [Pep 8](https://www.python.org/dev/peps/pep-0008/) coding conventions.
- Follow [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html) with the exception of using [Sphinx-style documentation](https://www.sphinx-doc.org/en/master/).
- Use imports for packages and modules only.
- Write your commit message in the imperative: "Fix bug" and not "Fixed bug" or "Fixes bug." This convention matches up with commit messages generated by commands like git merge and git revert.

## Updating Documentation
If you have found any mistakes, want to add examples, or just improve the documentation in general, you are more than welcome! Just make your change and send a pull request.

## Closing Words
Thank you for taking the time to read the Contributor's Guide!

VSHosting
