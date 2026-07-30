//! DepSentry 3D dependency-graph engine.
//!
//! Compiled to `wasm32-unknown-unknown` and driven from JavaScript. Rust owns
//! the simulation: force-directed layout in 3D, camera transform, perspective
//! projection, depth sorting and per-node visual state. JavaScript only reads
//! the resulting float buffers and rasterises them to a 2D canvas.
//!
//! # Why the raw C ABI rather than wasm-bindgen
//!
//! Every value crossing the boundary here is a scalar or a flat `f32` buffer,
//! so the generated glue wasm-bindgen would produce buys nothing. Exporting
//! `extern "C"` functions and letting JS read the linear memory directly keeps
//! the toolchain to `cargo build` alone and the binary in the tens of KB.
//!
//! # Memory model
//!
//! Two output buffers are allocated once at `graph_new` and reused every frame,
//! so the steady-state render loop performs no allocation:
//!
//! * node buffer — `NODE_STRIDE` floats per node
//! * edge buffer — `EDGE_STRIDE` floats per edge
//!
//! JS obtains the pointers once and wraps them in `Float32Array` views over the
//! wasm memory. The views stay valid because the buffers never reallocate.

#![allow(clippy::missing_safety_doc)]

use std::ptr;

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

/// sx, sy, radius, depth01, r, g, b, glow, pulse, ring
const NODE_STRIDE: usize = 10;
/// x1, y1, x2, y2, depth01, alpha, heat, width
const EDGE_STRIDE: usize = 8;

/// Node classification, mirrored in the JS side's colour legend.
const KIND_ROOT: u32 = 0;
const KIND_CLEAN: u32 = 1;
const KIND_UNREACHABLE: u32 = 2;
const KIND_REACHABLE: u32 = 3;

// Force-simulation tuning. These are the values that make the graph read as a
// structure rather than a hairball: strong short-range repulsion, weak springs,
// and just enough centring to keep it framed.
const REPULSION: f32 = 900.0;
const SPRING_K: f32 = 0.018;
const SPRING_LEN: f32 = 62.0;
const CENTER_PULL: f32 = 0.0016;
const DAMPING: f32 = 0.86;
const MAX_SPEED: f32 = 14.0;
/// Simulation never fully freezes -- a slow drift keeps the scene alive.
const ALPHA_FLOOR: f32 = 0.06;
const ALPHA_DECAY: f32 = 0.994;

// ---------------------------------------------------------------------------
// Small deterministic PRNG (xorshift32)
// ---------------------------------------------------------------------------

struct Rng(u32);

impl Rng {
    fn next_u32(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }

    /// Uniform in [-1, 1).
    fn signed(&mut self) -> f32 {
        (self.next_u32() as f32 / u32::MAX as f32) * 2.0 - 1.0
    }
}

// ---------------------------------------------------------------------------
// Graph state
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct Vec3 {
    x: f32,
    y: f32,
    z: f32,
}

struct Node {
    pos: Vec3,
    vel: Vec3,
    kind: u32,
    /// 0..10, drives radius and glow intensity.
    risk: f32,
    vulns: f32,
    /// Per-node phase offset so pulses don't beat in lockstep.
    phase: f32,
}

struct Edge {
    a: usize,
    b: usize,
    /// 1 when this edge lies on a reachable attack path.
    hot: u32,
}

struct Graph {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    node_out: Vec<f32>,
    edge_out: Vec<f32>,
    /// Painter's-algorithm ordering, back to front. Reused across frames.
    order: Vec<u32>,
    alpha: f32,
    hover: i32,
}

/// Single global instance. The wasm target is single-threaded, and holding a
/// raw pointer rather than a `static mut` reference avoids `static_mut_refs`.
static mut STATE: *mut Graph = ptr::null_mut();

#[inline]
unsafe fn state() -> Option<&'static mut Graph> {
    if STATE.is_null() {
        None
    } else {
        Some(&mut *STATE)
    }
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/// Allocate a graph of `n_nodes` / `n_edges`, replacing any previous one.
#[no_mangle]
pub unsafe extern "C" fn graph_new(n_nodes: u32, n_edges: u32, seed: u32) {
    if !STATE.is_null() {
        drop(Box::from_raw(STATE));
        STATE = ptr::null_mut();
    }

    let n = n_nodes as usize;
    let m = n_edges as usize;
    let mut rng = Rng(if seed == 0 { 0x9E37_79B9 } else { seed });
    // `rng` is consumed during seeding only; the running sim is deterministic.

    let mut nodes = Vec::with_capacity(n);
    for i in 0..n {
        // Seed on a jittered sphere: a random cube collapses into a blob and
        // takes far longer to unfold into a readable layout.
        let radius = 130.0 + rng.signed() * 40.0;
        let theta = (i as f32) * 2.399_963; // golden angle, even distribution
        let y = 1.0 - (i as f32 / (n.max(2) - 1) as f32) * 2.0;
        let r_xz = (1.0 - y * y).max(0.0).sqrt();

        nodes.push(Node {
            pos: Vec3 {
                x: theta.cos() * r_xz * radius,
                y: y * radius,
                z: theta.sin() * r_xz * radius,
            },
            vel: Vec3::default(),
            kind: KIND_CLEAN,
            risk: 0.0,
            vulns: 0.0,
            phase: (rng.next_u32() % 628) as f32 / 100.0,
        });
    }

    let graph = Graph {
        nodes,
        edges: Vec::with_capacity(m),
        node_out: vec![0.0; n * NODE_STRIDE],
        edge_out: vec![0.0; m * EDGE_STRIDE],
        order: (0..n as u32).collect(),
        alpha: 1.0,
        hover: -1,
    };

    STATE = Box::into_raw(Box::new(graph));
}

#[no_mangle]
pub unsafe extern "C" fn set_node(i: u32, kind: u32, risk: f32, vulns: f32) {
    if let Some(g) = state() {
        if let Some(node) = g.nodes.get_mut(i as usize) {
            node.kind = kind;
            node.risk = risk.clamp(0.0, 10.0);
            node.vulns = vulns.max(0.0);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn add_edge(a: u32, b: u32, hot: u32) {
    if let Some(g) = state() {
        let (a, b) = (a as usize, b as usize);
        if a < g.nodes.len() && b < g.nodes.len() && a != b {
            g.edges.push(Edge { a, b, hot });
            let needed = g.edges.len() * EDGE_STRIDE;
            if g.edge_out.len() < needed {
                g.edge_out.resize(needed, 0.0);
            }
        }
    }
}

/// Re-heat the simulation, e.g. after the user drags a node or reloads data.
#[no_mangle]
pub unsafe extern "C" fn reheat() {
    if let Some(g) = state() {
        g.alpha = 1.0;
    }
}

// ---------------------------------------------------------------------------
// Simulation
// ---------------------------------------------------------------------------

unsafe fn simulate(g: &mut Graph, dt: f32) {
    let n = g.nodes.len();
    if n == 0 {
        return;
    }

    let alpha = g.alpha;

    // Pairwise repulsion. O(n^2) is entirely adequate at the few-hundred-node
    // scale a dependency tree occupies; Barnes-Hut would be premature.
    for i in 0..n {
        let (pi, ri) = (g.nodes[i].pos, g.nodes[i].risk);
        let mut fx = 0.0;
        let mut fy = 0.0;
        let mut fz = 0.0;

        for j in 0..n {
            if i == j {
                continue;
            }
            let pj = g.nodes[j].pos;
            let dx = pi.x - pj.x;
            let dy = pi.y - pj.y;
            let dz = pi.z - pj.z;
            // Softening term prevents a singularity when two nodes coincide.
            let d2 = dx * dx + dy * dy + dz * dz + 12.0;
            let inv = REPULSION / d2;
            let d = d2.sqrt();
            fx += dx / d * inv;
            fy += dy / d * inv;
            fz += dz / d * inv;
        }

        // Risky nodes push a little harder, so hotspots get breathing room and
        // stay legible instead of being buried in the crowd.
        let boost = 1.0 + ri * 0.05;
        let node = &mut g.nodes[i];
        node.vel.x += fx * boost * alpha * dt;
        node.vel.y += fy * boost * alpha * dt;
        node.vel.z += fz * boost * alpha * dt;
    }

    // Spring attraction along dependency edges.
    for e in &g.edges {
        let pa = g.nodes[e.a].pos;
        let pb = g.nodes[e.b].pos;
        let dx = pb.x - pa.x;
        let dy = pb.y - pa.y;
        let dz = pb.z - pa.z;
        let dist = (dx * dx + dy * dy + dz * dz).sqrt().max(0.001);
        let f = (dist - SPRING_LEN) * SPRING_K * alpha * dt;
        let (ux, uy, uz) = (dx / dist, dy / dist, dz / dist);

        g.nodes[e.a].vel.x += ux * f;
        g.nodes[e.a].vel.y += uy * f;
        g.nodes[e.a].vel.z += uz * f;
        g.nodes[e.b].vel.x -= ux * f;
        g.nodes[e.b].vel.y -= uy * f;
        g.nodes[e.b].vel.z -= uz * f;
    }

    // Integrate with centring and damping.
    for node in g.nodes.iter_mut() {
        node.vel.x -= node.pos.x * CENTER_PULL;
        node.vel.y -= node.pos.y * CENTER_PULL;
        node.vel.z -= node.pos.z * CENTER_PULL;

        node.vel.x *= DAMPING;
        node.vel.y *= DAMPING;
        node.vel.z *= DAMPING;

        let speed = (node.vel.x * node.vel.x + node.vel.y * node.vel.y + node.vel.z * node.vel.z)
            .sqrt();
        if speed > MAX_SPEED {
            let s = MAX_SPEED / speed;
            node.vel.x *= s;
            node.vel.y *= s;
            node.vel.z *= s;
        }

        node.pos.x += node.vel.x;
        node.pos.y += node.vel.y;
        node.pos.z += node.vel.z;
    }

    g.alpha = (g.alpha * ALPHA_DECAY).max(ALPHA_FLOOR);
}

// ---------------------------------------------------------------------------
// Camera, projection, visual state
// ---------------------------------------------------------------------------

/// Advance one frame and write projected geometry into the output buffers.
///
/// `time` drives pulse animation. `yaw`/`pitch` are radians, `zoom` scales the
/// focal length, `mx`/`my` are cursor position in canvas pixels for hit testing.
#[no_mangle]
pub unsafe extern "C" fn step(
    dt: f32,
    yaw: f32,
    pitch: f32,
    zoom: f32,
    width: f32,
    height: f32,
    time: f32,
    mx: f32,
    my: f32,
) {
    let Some(g) = state() else { return };
    if g.nodes.is_empty() {
        return;
    }

    simulate(g, dt.clamp(0.2, 2.0));

    let (sy, cy) = yaw.sin_cos();
    let (sp, cp) = pitch.sin_cos();
    let cx = width * 0.5;
    let cyc = height * 0.5;
    let camera_dist = 520.0;
    let focal = height.max(1.0) * 0.9 * zoom.clamp(0.25, 4.0);

    // Rotate into camera space and record depth extent for normalisation.
    let n = g.nodes.len();
    let mut cam = Vec::with_capacity(n);
    let mut zmin = f32::MAX;
    let mut zmax = f32::MIN;

    for node in &g.nodes {
        // Yaw about Y, then pitch about X.
        let x1 = node.pos.x * cy + node.pos.z * sy;
        let z1 = -node.pos.x * sy + node.pos.z * cy;
        let y2 = node.pos.y * cp - z1 * sp;
        let z2 = node.pos.y * sp + z1 * cp;

        zmin = zmin.min(z2);
        zmax = zmax.max(z2);
        cam.push(Vec3 { x: x1, y: y2, z: z2 });
    }

    let zspan = (zmax - zmin).max(0.001);

    // Project and write node visual state.
    let mut best_hit = -1_i32;
    let mut best_hit_d2 = f32::MAX;

    for (i, node) in g.nodes.iter().enumerate() {
        let c = cam[i];
        let denom = (camera_dist - c.z).max(20.0);
        let scale = focal / denom;
        let sx = cx + c.x * scale;
        let sy_px = cyc + c.y * scale;
        let depth01 = (c.z - zmin) / zspan;

        // Radius: base size by role, grown by risk, scaled by perspective.
        let base = match node.kind {
            KIND_ROOT => 13.0,
            KIND_REACHABLE => 7.0 + node.risk * 0.55,
            KIND_UNREACHABLE => 5.0 + node.risk * 0.16,
            _ => 4.2,
        };
        let radius = (base * scale * 1.9).clamp(1.6, 46.0);

        let pulse = if node.kind == KIND_REACHABLE {
            // Reachable = live threat. Pulse hard so the eye is pulled there.
            0.5 + 0.5 * (time * 2.6 + node.phase).sin()
        } else if node.kind == KIND_ROOT {
            0.5 + 0.5 * (time * 1.1 + node.phase).sin()
        } else {
            0.0
        };

        let (r, gg, b, glow) = match node.kind {
            KIND_ROOT => (0.62, 0.94, 1.0, 0.85),
            KIND_REACHABLE => {
                // Amber at low risk through to hot red at CVSS-10 equivalent.
                let t = (node.risk / 10.0).clamp(0.0, 1.0);
                (1.0, 0.42 - 0.30 * t, 0.22 - 0.14 * t, 0.75 + 0.25 * pulse)
            }
            KIND_UNREACHABLE => (0.62, 0.55, 0.30, 0.20),
            _ => (0.40, 0.52, 0.68, 0.13),
        };

        // Depth cue: distant nodes recede.
        let fade = 0.42 + 0.58 * depth01;

        let o = i * NODE_STRIDE;
        g.node_out[o] = sx;
        g.node_out[o + 1] = sy_px;
        g.node_out[o + 2] = radius;
        g.node_out[o + 3] = depth01;
        g.node_out[o + 4] = r;
        g.node_out[o + 5] = gg;
        g.node_out[o + 6] = b;
        g.node_out[o + 7] = glow * fade;
        g.node_out[o + 8] = pulse;
        g.node_out[o + 9] = if node.vulns > 0.0 { 1.0 } else { 0.0 };

        // Hit test: nearest node under the cursor, front-most wins ties.
        let ddx = sx - mx;
        let ddy = sy_px - my;
        let d2 = ddx * ddx + ddy * ddy;
        let hit_r = (radius + 6.0) * (radius + 6.0);
        if d2 < hit_r && d2 - depth01 * 40.0 < best_hit_d2 {
            best_hit_d2 = d2 - depth01 * 40.0;
            best_hit = i as i32;
        }
    }

    g.hover = best_hit;

    // Project edges.
    for (k, e) in g.edges.iter().enumerate() {
        let ca = cam[e.a];
        let cb = cam[e.b];

        let sa = focal / (camera_dist - ca.z).max(20.0);
        let sb = focal / (camera_dist - cb.z).max(20.0);
        let depth01 = (((ca.z + cb.z) * 0.5) - zmin) / zspan;

        let o = k * EDGE_STRIDE;
        g.edge_out[o] = cx + ca.x * sa;
        g.edge_out[o + 1] = cyc + ca.y * sa;
        g.edge_out[o + 2] = cx + cb.x * sb;
        g.edge_out[o + 3] = cyc + cb.y * sb;
        g.edge_out[o + 4] = depth01;

        if e.hot == 1 {
            // Energy travelling along a live attack path.
            let flow = 0.5 + 0.5 * (time * 3.4 - (k as f32) * 0.6).sin();
            g.edge_out[o + 5] = 0.30 + 0.55 * flow * (0.4 + 0.6 * depth01);
            g.edge_out[o + 6] = 1.0;
            g.edge_out[o + 7] = 1.5 + 1.4 * flow;
        } else {
            g.edge_out[o + 5] = 0.05 + 0.10 * depth01;
            g.edge_out[o + 6] = 0.0;
            g.edge_out[o + 7] = 0.7;
        }
    }

    // Painter's algorithm: insertion sort over the retained order. Frame-to-
    // frame coherence makes this effectively linear after the first sort.
    let ord = &mut g.order;
    if ord.len() != n {
        *ord = (0..n as u32).collect();
    }
    for i in 1..n {
        let key = ord[i];
        let kd = g.node_out[key as usize * NODE_STRIDE + 3];
        let mut j = i;
        while j > 0 && g.node_out[ord[j - 1] as usize * NODE_STRIDE + 3] > kd {
            ord[j] = ord[j - 1];
            j -= 1;
        }
        ord[j] = key;
    }
}

// ---------------------------------------------------------------------------
// Accessors for the JS side
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn nodes_ptr() -> *const f32 {
    state().map_or(ptr::null(), |g| g.node_out.as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn edges_ptr() -> *const f32 {
    state().map_or(ptr::null(), |g| g.edge_out.as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn order_ptr() -> *const u32 {
    state().map_or(ptr::null(), |g| g.order.as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn node_count() -> u32 {
    state().map_or(0, |g| g.nodes.len() as u32)
}

#[no_mangle]
pub unsafe extern "C" fn edge_count() -> u32 {
    state().map_or(0, |g| g.edges.len() as u32)
}

#[no_mangle]
pub unsafe extern "C" fn hovered() -> i32 {
    state().map_or(-1, |g| g.hover)
}

#[no_mangle]
pub extern "C" fn node_stride() -> u32 {
    NODE_STRIDE as u32
}

#[no_mangle]
pub extern "C" fn edge_stride() -> u32 {
    EDGE_STRIDE as u32
}
