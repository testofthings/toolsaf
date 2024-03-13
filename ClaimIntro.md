# Claims

The framework can be used to define _claims_ (also called tests) to verify the the model is accurate and describes the security posture of the system.
In the framework a _requirement_ is made up of a _selector_ and the _claim_.
The selector chooses the model elements which the claim targets.

## Defining requirements

Default requirements, and thus claims, are defined in class `DefaultSpecification` defined in file `tcsfw.default_requirements`.
They are used in the 2023 article "_Transparent Security Method for Automating IoT Security Assessments_".

Specificaiton defines requirements in the __init__ method. Consider the first requirement from the default set:

```python
self.no_unexpected_nodes = self._add(
    "no-unexp-nodes",
    Select.host(unexpected=True) ^ Claim.expected("Network nodes are defined"))

```

The method `_add` adds a requirement identifier and the requirement to the specification.

Selectors are created by class methods of the factory `Select`.
Claims are either defined by the class methods of factory `Claim` or the claim classes are created directly.
Operator `^` separates the selector and claim.

See classes `Select` and `Claim` for available selectors and claims.

## More information

This features is very much under development.
Please, take a look of modules `tcsfw.default_requirements` and `tcsfw.etsi_ts_103_701` to see the claims and tests used in the research publications.
