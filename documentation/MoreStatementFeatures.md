# More security statement features

[Table of contents](README.md)

## Masking False Positive Tool Outputs
Depending on the situation, one or more findings made by security tools may be false positives.

Let's say we have a backend service serving TLS, and we test it with _testssl_.
```python
backend = system.backend("Backend").serve(TLS)
```
In this scenario, running the statement with the _testssl_ results would produce the following output:
```shell
[Expected/Fail]  Backend
[Expected/Fail]  └──TLS:443
[Fail]              └──testssl:BREACH # Testssl.sh (BREACH): potentially VULNERABLE, gzip HTTP compression detected  - only supplied '/' tested
```
After reviewing the result, we determine that the `testssl:BREACH` property added to the Backend's TLS service is not actually an issue since it can't be exploited. To mask its fail verdict, we can add the following addendum to the security statement:
```python
system.ignore(file_type="testssl").properties(
    "testssl:BREACH" # Testssl.sh (BREACH): potentially VULNERABLE, gzip HTTP compression detected  - only supplied '/' tested
).at(backend / TLS).because("Not exploitable")
```
The above statement creates a new false positive masking rule. Here is a breakdown of the DSL statement:

1. **`ignore(file_type="testssl")`**: Creates a new ignore rule that applies to result files of type `testssl`. The file types are the same as those used in _00meta.json_ files. Check them out [here](Tools.md#list-of-supported-tools).
2. **`properties("testssl:BREACH")`**: Specifies that the `"testssl:BREACH"` property should be masked. `properties()` can be used with zero or more arguments. Calling it with zero arguments masks all properties for the given `file_type`. A good practice is to also add the property's description (if any) as a comment after the actual property.
3. **`at(backend / TLS)`**: Makes the masking rule apply only to the specified service. If `at()` is not used, the rule will apply everywhere.
4. **`because("Not exploitable")`**: Allows you to add a reason for the masking in the statement.

If the statement is run again with this addition, the output would be as follows:
```shell
[Expected/Pass]  Backend
[Expected/Pass]  └──TLS:443
[Ignore]            └──testssl:BREACH # Not exploitable
```

Further examples of using `ignore()` to mask false positives can be found in the [Ruuvi security statement](https://github.com/testofthings/statement-ruuvi/blob/main/ruuvi/statement.py).

### Determining if a Finding is a False Positive

The task of determining whether or not a tool finding is a false positive is left to the security statement's creator. Here are some tips to help you with that:

* Check tool output files, as some contain additional information on the found issues.
* Check the documentation of used tools on their own websites (or maybe even their source code).
* Information on Common Vulnerabilities and Exposures (CVEs) can be found using your favorite search engine.
* Consider findings within the context of the specific IoT system. What may be a critical vulnerability in one setup might be harmless in another due to different configurations or implementations.

An understanding of the tools used and the system will help you make informed decisions about handling findings.

## Mobile Application Permissions (Android Only)

Mobile operating systems, such as Android, run applications in isolated sandboxes and
allowed actions are controlled by _permissions_.
An application that uses excessive permissions is a security risk.
For example, an application may collect sensitive information about its users and upload it to a backend system.
Even when the application vendor respects users' rights, the information may end up in the wrong hands
due to security breaches.
Thus, the fewer permissions an application asks for, the less risk it poses to the user.

Mobile applications must ask for permissions. These permissions should be included in the security statement. You can define them with:
```python
from toolsaf.common.android import STORAGE, LOCATION, ...

mobile.set_permissions(STORAGE, LOCATION, ...)
```
However, since there are [hundreds of different permissions](https://developer.android.com/reference/android/Manifest.permission), **use the permission categories we have created** in your security statements. Toolsaf handles the rest.

Our permission categories are: `CALLS`, `SMS`, `CONTACTS`, `CALENDAR`, `LOCATION`, `RECORDING`, `STORAGE`, `NETWORK`, `HEALTH`, `ACCOUNT`, `BILLING`, `BLUETOOTH`, `ADMINISTRATIVE`, `UNCATEGORIZED`

An up-to-date list of categories can always be found [here](../toolsaf/common/android.py). You can check into which category a permission belongs from [this json file](../toolsaf/adapters/data/android_permissions.json). Currently, if a permission is not in the _.json_ file, its category will be `UNCATEGORIZED`.

## Online Resources

Our DSL provides the `online_resources(name, url, keywords)` method to document web-based information relevant to the system, such as privacy, security, and cookie policies. However, any web page can be defined.

Online resources can be added to the security statement using the following syntax:
```python
system.online_resource(
    name="privacy-policy",
    url="https://example.com/privacy/",
    keywords=["privacy policy", "personal data", ...]
)
```
It is recommended to name online resources descriptively, based on their purpose. For example, a link to a vulnerability policy should be named `vulnerability-policy`.

In addition to the `name` and the resource's `url`, `online_resource` also requires the user to provide a list of keywords. You can decide what keywords to add. However, they should all be found on the page. These keywords are used during verification to ensure that the page and its contents were actually accessible during the verification process.
