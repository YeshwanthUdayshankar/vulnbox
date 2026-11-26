import test from "node:test";
import assert from "node:assert/strict";
import { readPublicFile } from "../server.mjs";

test("reads public readme file", () => {
  const content = readPublicFile("readme.txt");
  assert.match(content, /Hello from node_sample_app!/);
});
