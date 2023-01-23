## AIDL error handling

Starting in **Android U (14)**, `libmediadrm` (app-side) understands extra error
details from **AIDL** DRM HALs passed through the binder exception message
as a json string. The supported fields are:
* `cdmError` (*int*)
* `oemError` (*int*)
* `context` (*int*)
* `errorMessage` (*str*)

The errors details will be reported to apps through the java interface
`android.media.MediaDrmThrowable`. Please see the javadoc of `MediaDrmThrowable`
for detailed definitions of each field above.
