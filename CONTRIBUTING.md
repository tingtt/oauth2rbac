# Contributing to oauth2rbac

Thank you for considering contributing to the project! We welcome contributions in all forms.

## Code of Conduct

Please adhere to the [Go Community Code of Conduct](https://go.dev/conduct) when interacting with others in the project.

## How to Contribute

1. Fork the repository.
2. Create a new branch (`git checkout -b my-feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -m 'Add some feature'`).
5. Push to the branch (`git push origin my-feature-branch`).
6. Create a new Pull Request.

## Build

### Docker

To build the Docker image, use the following command:

````bash
docker build --build-arg GO_ENTRYPOINT='cmd/proxy/main.go' .
````

## Testing

### Test code

```sh
make test
# will run `go test ./... -parallel 10`
```

### E2E (manual)

Please refer to the [End-to-End Testing Guide](./test/e2e/README.md) for instructions on how to run tests.

## Issue Reporting

If you encounter a bug or have a feature request, please open an issue in the GitHub repository.
