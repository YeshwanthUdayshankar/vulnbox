import assert from "node:assert/strict";
import test from "node:test";
import { dispatchAction, registerRequestListener } from "../server.mjs";

test("dispatchAction stores item and listener registers", () => {
  assert.ok(dispatchAction("store", "unit_k") >= 1);
  assert.ok(registerRequestListener() >= 0);
});
