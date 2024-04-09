# Tcsfw roadmap

The following provides a rough overview of how we see the tcsfw framework developing towards useful security assessment toolkit.

## Core features

The following features are planned in the core functionality of the framework: security statements, claims, tool output processing, verdict assignment.

 * Add and update features required when new security statements are created
 * Improve performace with larger sets of tool data to process
 * Test integration with production-grade SQL databasese
 * Introduce code quality and security tools (e.g. _pylint_) 

## Web API 

The following features are planned for the _Web API_ of the framework

 * User authentication
 * Upload tool output
 * Pull assessment results to be used in other systems
 * Formal documentaiton using _OpenAPI_


## Deployment

The framework should be deployed for production use. This is envisioned using _Open container_ format.

 * Build official container image of the framework

## Test execution support

At the moment, one must collect and present the tool outputs manually, which is not how things are suppoed to work.

 * Add a tool to upload tool output into deployed framework instance


