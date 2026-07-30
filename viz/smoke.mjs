// Headless smoke test for the Rust/WASM engine.
//   node viz/smoke.mjs viz/target/wasm32-unknown-unknown/release/depsentry_viz.wasm
//
// Verifies the C ABI surface, then runs 240 simulation frames and asserts the
// output buffers stay finite, the layout stays framed, and the painter order
// is sorted back-to-front. Catches numerical blow-ups the browser would only
// show as a blank canvas.

import { readFileSync } from "fs";
const bytes = readFileSync(process.argv[2]);
const { instance } = await WebAssembly.instantiate(bytes, {});
const w = instance.exports;

const need = ["graph_new","set_node","add_edge","step","nodes_ptr","edges_ptr",
              "order_ptr","node_count","edge_count","hovered","node_stride","edge_stride","reheat"];
const missing = need.filter(n => typeof w[n] !== "function");
if (missing.length) { console.error("MISSING EXPORTS:", missing); process.exit(1); }
console.log("exports OK:", need.length);

const N = 28, E = 27;
w.graph_new(N, E, 0x5EED);
for (let i = 0; i < N; i++) w.set_node(i, i === 0 ? 0 : (i % 4), (i % 10), i % 3);
for (let i = 1; i < N; i++) w.add_edge(Math.floor(i / 3), i, i % 5 === 0 ? 1 : 0);

console.log("node_count:", w.node_count(), "edge_count:", w.edge_count(),
            "strides:", w.node_stride(), w.edge_stride());

const NS = w.node_stride(), ES = w.edge_stride();
const mem = w.memory.buffer;
const nodes = new Float32Array(mem, w.nodes_ptr(), N * NS);
const edges = new Float32Array(mem, w.edges_ptr(), w.edge_count() * ES);
const order = new Uint32Array(mem, w.order_ptr(), N);

// Run 240 frames (~4s of animation) and assert the sim stays finite & framed.
let t = 0;
for (let f = 0; f < 240; f++) { t += 1/60; w.step(1.0, 0.6 + t*0.2, -0.24, 1.0, 1200, 700, t, 600, 350); }

const bad = [...nodes].filter(v => !Number.isFinite(v));
if (bad.length) { console.error("NON-FINITE VALUES in node buffer:", bad.length); process.exit(1); }
if ([...edges].some(v => !Number.isFinite(v))) { console.error("NON-FINITE in edge buffer"); process.exit(1); }
console.log("all values finite after 240 frames");

let inFrame = 0, minR = 1e9, maxR = -1e9;
for (let i = 0; i < N; i++) {
  const x = nodes[i*NS], y = nodes[i*NS+1], r = nodes[i*NS+2];
  if (x > -400 && x < 1600 && y > -400 && y < 1100) inFrame++;
  minR = Math.min(minR, r); maxR = Math.max(maxR, r);
}
console.log(`nodes near frame: ${inFrame}/${N}   radius range: ${minR.toFixed(2)}..${maxR.toFixed(2)}`);
if (inFrame < N * 0.8) { console.error("layout escaped the viewport"); process.exit(1); }

// depth ordering must be ascending (painter's algorithm, back to front)
let sorted = true;
for (let i = 1; i < N; i++)
  if (nodes[order[i-1]*NS+3] > nodes[order[i]*NS+3] + 1e-6) { sorted = false; break; }
console.log("painter order sorted back-to-front:", sorted);
if (!sorted) process.exit(1);

const hot = [...Array(w.edge_count())].filter((_,k) => edges[k*ES+6] === 1).length;
console.log("hot edges:", hot);
console.log("hover hit-test at centre:", w.hovered());
console.log("\nWASM SMOKE TEST PASSED");
