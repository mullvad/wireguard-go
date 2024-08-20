# Changelog
All notable changes are recorded here.

### Format

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

Entries should have the imperative form, just like commit messages. Start each entry with words like
add, fix, increase, force etc.. Not added, fixed, increased, forced etc.

Line wrap the file at 100 chars.                                              That is over here -> |

### Categories each change fall into

* **Added**: for new features.
* **Changed**: for changes in existing functionality.
* **Deprecated**: for soon-to-be removed features.
* **Removed**: for now removed features.
* **Fixed**: for any bug fixes.
* **Security**: in case of vulnerabilities.

## [Unreleased]
### Fixed
- Fix netstack tunnel leaking when closed.
- Fix race when closing the DAITA event channel, which could result in events being sent on the
  closed channel.


## [0.1.0] - 2024-07-25
### Added
- Initial DAITA release.
