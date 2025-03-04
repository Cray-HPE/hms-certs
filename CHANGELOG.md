# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.0] - 2025-03-04

### Security

- Update module dependencies
- Code changes related to updating hms-base and adding hms-xname

## [1.5.0] - 2024-12-02

### Changed

- updated go to 1.23

## [1.4.0] - 2022-06-10

### Changed

- FetchCA() and CreateCert() to use the hms-securestorage library for vault operations.

## [1.3.3] - 2021-08-09

### Changed

- Added GitHub configuration files and fixed snyk warning.

## [1.3.2] - 2021-07-22

### Changed

- Changed all references to stash to GitHub.

## [1.3.1] - 2021-07-20

### Changed

- Add support for building within the CSM Jenkins.

## [1.3.0] - 2021-06-28

### Security

- CASMHMS-4898 - Updated base container images for security updates.

## [1.2.2] - 2021-04-14

### Changed

- Fixed HTTP response leaks.

## [1.2.1] - 2021-04-06

### Changed

- Updated Dockerfiles to pull base images from Artifactory instead of DTR.

## [1.2.0] - 2021-01-27

### Changed

- Update copyright/license info in source files.

## [1.1.1] - 2021-01-21

### Changed

- Added User-Agent headers to all outbound HTTP requests.

## [1.1.0] - 2021-01-14

### Changed

- Updated license file.


## [1.0.7] - 2020-10-30

- Added ability to create retryable HTTPClientPair objects.

## [1.0.6] - 2020-10-26

- Better checking for uninitialized HTTPClientPair objects.

## [1.0.5] - 2020-10-20

- CASMHMS-4105 - Updated base Golang Alpine image to resolve libcrypto vulnerability.

## [1.0.4] - 2020-10-12

- Added FailedOver flag to HTTPClientPair object.

## [1.0.3] - 2020-10-06

- Fixup of XName handling of PDUs.  Support to shut off TLS failover logging.

## [1.0.2] - 2020-09-09

- Added PDU and CMM endpoints in the cabinet domain SANS for leaf certs.

## [1.0.1] - 2020-09-01

- Now creates 2 identical insecure HTTP transports if CA URI is empty.

## [1.0.0] - 2020-07-28

- Initial commit.

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

