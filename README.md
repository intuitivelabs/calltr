# calltr

The calltr package provides SIP call tracking and event generation
support.

It will try to reconstruct dialog and registration state even if messages
are missing.

### Events

An event callback can be set, that will be called for each call-state
 related event.

See [sipcmbeat](https://github.com/intuitivelabs/sipcmbeat/README.md) for
 the list of the supported events.


### Dependencies

calltr depends on [sipsp](https://github.com/intuitivelabs/sipsp).
