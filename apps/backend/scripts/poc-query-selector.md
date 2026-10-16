# Query-selector injection PoC

This reproduces the unchecked `projectId` in `POST /api/simulations`
(`src/routes.js`). It does not demonstrate login bypass, access to another
account's projects, or code execution through MongoDB.

## Query casting without a database

With the backend dependencies installed, run from the repository root:

```sh
node apps/backend/scripts/poc-query-selector.mjs
```

Expected with the locked Mongoose 8.24.5 dependency:

```text
"507f1f77bcf86cd799439011" -> {"_id":"507f1f77bcf86cd799439011"}
{"$ne":null} -> {"_id":{"$ne":null}}
{"$in":["507f1f77bcf86cd799439011"]} -> {"_id":{"$in":["507f1f77bcf86cd799439011"]}}
```

`$ne` survives as a MongoDB selector instead of being rejected as an invalid ID.
The script constructs and casts queries only: no database connection or writes.

## Test your local endpoint

Choose a harmless test project you own. Set `HDLAB_TOKEN` through your shell's
environment using your existing account token, then run:

```sh
node apps/backend/scripts/poc-query-selector.mjs \
  --url http://localhost:8080 \
  --project-id YOUR_24_CHARACTER_PROJECT_ID
```

The script first verifies access through `GET /api/projects/:id`, then sends one
request containing `{"projectId":{"$in":["YOUR_PROJECT_ID"]},"testbenchType":"systemverilog"}`.
This demonstrates the same acceptance of an operator object while restricting
the query to your exact project. A broad `$ne` selector could select a different
account's project, which the existing ownership check would reject, making it
an unreliable endpoint demonstration.

A `201` response with the requested project ID confirms acceptance and creates
one simulation, which the worker may execute. The script does not poll, retry,
create projects, or delete records. A timeout can still leave a simulation created.
HTTP mode requires Node 18+ but does not load Mongoose.

After a fix, the endpoint should return `400` specifically for an invalid
`projectId` before querying the database. The standalone casting demonstration
will still succeed if the fix is implemented in route validation.
