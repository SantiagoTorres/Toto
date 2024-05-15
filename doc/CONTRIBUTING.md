# Contributing to in-toto
Thank you for your interest in contributing to in-toto! We welcome contributions from the community to help improve and enhance the project.

# Quick Start Guide
To get started with contributing to in-toto, follow these steps:

## 1. Clone the Repository
Clone the in-toto git repository to your local machine:

```sh
git clone https://github.com/in-toto/in-toto.git
```

## 2. Install Development Dependencies
Navigate to the project root directory and install development dependencies using pip:

```sh
pip install -r requirements-dev.txt
```

## 3. Review Contribution Guidelines
Before contributing, please review our [contribution guidelines](https://github.com/in-toto/community/blob/main/CONTRIBUTING.md) to ensure that your code follows our style guidelines and is properly tested.

## 4. Sign the Developer Certificate of Origin (DCO)
All contributors must sign the Developer Certificate of Origin (DCO) by adding a "Signed-off-by" line to their commit messages. This indicates your acceptance of the DCO. You can do this by appending the following line to each commit message:

```kotlin
Signed-off-by: Your Name <example@domain.com>
```

## 5. Run Tests
Run the test suite using tox to ensure that your changes do not introduce any regressions:

```sh
tox 
```

This will execute the entire test suite in a separate virtual environment for each supported Python version.

## Additional Testing
### Manual Testing
You can also run individual tests or the test suite manually if needed:

```sh
# Run individual tests
python runtests.py <test_file.py>

# Run entire test suite
python runtests.py
```

## Code Formatting
Ensure that your code follows the required formatting standards by using black and isort:

```sh
# Auto-format code with black
black .

# Sort imports with isort
isort .
```

## Build Documentation
If you make changes to the documentation, build the HTML documentation locally:

```sh
cd doc && make html
```