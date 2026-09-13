# Enforce document ownership at the data boundary

`server.py` adapts authenticated document API requests to `documents.handle`. The `actor` context is supplied by a trusted authentication layer; it is either null or `{tenant,user}`. Fix the existing object-authorization bug for both reads and updates.

Null actors receive `{status:401}`. A document is accessible only when both its tenant and owner equal the actor's tenant and user. Missing or inaccessible documents return `{status:404}` without revealing the body. Successful reads return `{status:200,body:<text>}`; updates return `{status:204}`. An unauthorized update must not change any row. Preserve the existing document schema and data and use parameterized queries. The same username can exist in multiple tenants.

The public smoke case is Amy reading n1. Independent checks exercise another owner's document, a cross-tenant identity, unauthorized and authorized updates, missing IDs, and final stored content.
