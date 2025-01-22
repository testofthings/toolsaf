# More security statement features

[Table of contents](README.md)

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
