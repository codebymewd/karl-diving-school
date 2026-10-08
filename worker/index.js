// Karl Phelps Driving School API (Cloudflare Worker). All reads/writes go through here; clients never touch Firestore directly.
const enc = new TextEncoder();
const b64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const J = (o, status, h) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json", ...h } });
class HttpError extends Error { constructor(s, m) { super(m); this.status = s; } }
const bad = (m, s = 400) => { throw new HttpError(s, m); };
const iso = () => new Date().toISOString();
const str = (x, max) => (typeof x === "string" ? x.trim().slice(0, max) : "");
const PHONE = /^(\+234|0)[789][01]\d{8}$/;
const TYPES = ["Online Theory", "Simulation", "Manual Driving", "Automatic Driving", "CBT Preparation", "Other"];
const REASONS = ["I was unavailable", "Internet/network problem", "Emergency", "I forgot", "Other"];
const DEFAULT_REQ = { "Online Theory": 8, "Simulation": 4, "Manual Driving": 6, "Automatic Driving": 6, "CBT Preparation": 2 };
const DEFAULT_PACKAGES = [
  { id: "weekday", name: "Weekday Package", desc: "Basic Defensive Driver Course on weekdays.", options: [{ label: "Monday to Friday", duration: "5 weeks", price: 95000 }, { label: "3 weekday sessions per week", duration: "8 weeks", price: 95000 }] },
  { id: "weekend", name: "Weekend Package", desc: "Basic Defensive Driver Course at weekends.", options: [{ label: "Friday and Saturday", duration: "6 weeks", price: 100000 }, { label: "Saturday only", duration: "7 weeks", price: 100000 }] },
  { id: "fast-track", name: "Fast Track", desc: "Complete your training in the shortest time.", options: [{ label: "Intensive", duration: "9 days", price: 150000 }, { label: "Extended", duration: "13 days", price: 130000 }] },
];

// ---------- Firebase token + service account ----------
async function verifyIdToken(token, env) {
  const [h, p, s] = (token || "").split(".");
  if (!s) bad("Not signed in", 401);
  const head = JSON.parse(new TextDecoder().decode(unb64u(h)));
  const pay = JSON.parse(new TextDecoder().decode(unb64u(p)));
  const jwks = await (await fetch("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com", { cf: { cacheTtl: 3600 } })).json();
  const jwk = jwks.keys.find((k) => k.kid === head.kid);
  if (head.alg !== "RS256" || !jwk) bad("Invalid token", 401);
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, unb64u(s), enc.encode(h + "." + p));
  if (!ok || pay.aud !== env.FIREBASE_PROJECT_ID || pay.iss !== "https://securetoken.google.com/" + env.FIREBASE_PROJECT_ID || pay.exp < Date.now() / 1000 || !pay.sub) bad("Invalid token", 401);
  return pay;
}
let cached = { v: null, exp: 0 };
async function accessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (cached.v && cached.exp > now + 60) return cached.v;
  const head = b64u(enc.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const claim = b64u(enc.encode(JSON.stringify({ iss: env.FB_CLIENT_EMAIL, scope: "https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/identitytoolkit", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 })));
  const pem = env.FB_PRIVATE_KEY.replace(/\\n/g, "\n").replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  const key = await crypto.subtle.importKey("pkcs8", Uint8Array.from(atob(pem), (c) => c.charCodeAt(0)), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(head + "." + claim));
  const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: head + "." + claim + "." + b64u(sig) }) });
  const j = await r.json();
  if (!j.access_token) throw new Error("Service account auth failed");
  cached = { v: j.access_token, exp: now + 3000 };
  return cached.v;
}
const H = async (env) => ({ Authorization: "Bearer " + (await accessToken(env)), "Content-Type": "application/json" });
const ITK = (env) => `https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}`;
async function authUpdate(env, body) { const r = await fetch(ITK(env) + "/accounts:update", { method: "POST", headers: await H(env), body: JSON.stringify(body) }); if (!r.ok) throw new Error("Auth update failed"); }
const setClaims = (env, uid, claims) => authUpdate(env, { localId: uid, customAttributes: JSON.stringify(claims) });
async function createAuthUser(env, email, password, displayName) {
  const r = await fetch(ITK(env) + "/accounts", { method: "POST", headers: await H(env), body: JSON.stringify({ email, password, displayName, emailVerified: true }) });
  const j = await r.json();
  if (!r.ok) { if (String(j.error?.message).includes("EMAIL_EXISTS")) bad("That email is already in use", 409); throw new Error("Could not create user"); }
  return j.localId;
}

// ---------- Firestore (REST) ----------
const base = (env) => `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents`;
const docName = (env, path) => `projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/${path}`;
const val = (v) => (typeof v === "number" ? { integerValue: String(v) } : typeof v === "boolean" ? { booleanValue: v } : { stringValue: String(v) });
const fields = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v != null && v !== "").map(([k, v]) => [k, val(v)]));
const plain = (f) => Object.fromEntries(Object.entries(f || {}).map(([k, v]) => [k, v.stringValue ?? (v.integerValue != null ? Number(v.integerValue) : v.booleanValue)]));
const W = (env, path, o, mask) => { const f = fields(o); return { update: { name: docName(env, path), fields: f }, ...(mask ? { updateMask: { fieldPaths: Object.keys(f) } } : {}) }; };
async function getDoc(env, path) {
  const r = await fetch(`${base(env)}/${path}`, { headers: await H(env) });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error("Firestore read failed");
  return plain((await r.json()).fields);
}
async function list(env, col, where = {}, limit = 300, order) {
  const filters = Object.entries(where).map(([k, v]) => ({ fieldFilter: { field: { fieldPath: k }, op: "EQUAL", value: val(v) } }));
  const q = { from: [{ collectionId: col }], limit };
  if (filters.length === 1) q.where = filters[0]; else if (filters.length > 1) q.where = { compositeFilter: { op: "AND", filters } };
  if (order && !filters.length) q.orderBy = [{ field: { fieldPath: order }, direction: "DESCENDING" }];
  const r = await fetch(`${base(env)}:runQuery`, { method: "POST", headers: await H(env), body: JSON.stringify({ structuredQuery: q }) });
  const j = await r.json();
  if (!r.ok) throw new Error("Firestore query failed");
  return j.filter((x) => x.document).map((x) => ({ id: x.document.name.split("/").pop(), ...plain(x.document.fields) }));
}
async function commit(env, writes) {
  const r = await fetch(`${base(env)}:commit`, { method: "POST", headers: await H(env), body: JSON.stringify({ writes }) });
  const j = await r.json();
  if (!r.ok) throw new HttpError(j.error?.status === "ALREADY_EXISTS" ? 409 : 500, "Could not save record");
  return j;
}
const put = (env, path, o) => commit(env, [W(env, path, o)]);
const patch = (env, path, o) => commit(env, [W(env, path, o, true)]);
const del = (env, path) => commit(env, [{ delete: docName(env, path) }]);
async function nextNum(env, name) {
  const r = await commit(env, [{ transform: { document: docName(env, "counters/" + name), fieldTransforms: [{ fieldPath: "n", increment: { integerValue: "1" } }] } }]);
  return Number(r.writeResults[0].transformResults[0].integerValue);
}
const notify = (env, to, title, body) => put(env, "notifications/" + crypto.randomUUID(), { ...to, title, body, read: false, at: iso() }).catch(() => {});
const audit = (env, uid, action, ref, meta) => put(env, "auditLogs/" + crypto.randomUUID(), { uid, action, ref, meta: meta ? JSON.stringify(meta) : "", at: iso() }).catch(() => {});
const notifyPackage = async (env, packageId, title, body) => { const e = await list(env, "enrollments", { packageId, status: "Active" }, 300); await Promise.all(e.map((x) => notify(env, { toUid: x.uid }, title, body))); };
const effStatus = (s, now = iso()) => (s.status === "Ended" || now >= s.endAt ? "Ended" : now >= s.startAt ? "Started" : "Scheduled");
const lagosTime = (t) => new Date(t).toLocaleTimeString("en-NG", { timeZone: "Africa/Lagos", hour: "numeric", minute: "2-digit" });
const lagosDay = (t) => new Date(Date.parse(t) + 36e5).toISOString().slice(0, 10);

async function getPackages(env) {
  const d = await list(env, "packages");
  if (!d.length) return DEFAULT_PACKAGES;
  return d.filter((x) => x.active !== false).sort((a, b) => (a.order || 0) - (b.order || 0)).map((x) => ({ id: x.id, name: x.name, desc: x.desc, options: JSON.parse(x.options || "[]") }));
}
const requirements = async (env) => { try { return JSON.parse((await getDoc(env, "settings/school"))?.requirements) || DEFAULT_REQ; } catch { return DEFAULT_REQ; } };
async function proofUrl(env, pid) {
  if (!pid) return null;
  const sig = b64u(await crypto.subtle.digest("SHA-1", enc.encode(pid + env.CLOUDINARY_API_SECRET))).slice(0, 8);
  return `https://res.cloudinary.com/${env.CLOUDINARY_CLOUD}/image/authenticated/s--${sig}--/${pid}`;
}

// ---------- gates ----------
async function gateStudent(env, user) {
  if (user.role !== "student") bad("Forbidden", 403);
  const u = await getDoc(env, "users/" + user.sub);
  if (!u || u.status !== "active") bad("Account inactive", 403);
}
async function gateStaff(env, user, adminOnly) {
  if (!["admin", "instructor"].includes(user.role) || (adminOnly && user.role !== "admin")) bad("Forbidden", 403);
  const u = await getDoc(env, "users/" + user.sub);
  if (!u || u.status !== "active" || u.role !== user.role) bad("Account inactive or suspended", 403); // suspension takes effect immediately
}

// ---------- student ----------
async function registerStudent(env, user, b) {
  if (user.role && user.role !== "student") bad("Staff accounts cannot register as students", 403);
  const existing = await getDoc(env, "students/" + user.sub);
  if (existing) return { studentId: existing.studentId };
  const p = { fullName: str(b.fullName, 100), phone: str(b.phone, 20), address: str(b.address, 200), dob: str(b.dob, 10), emergencyName: str(b.emergencyName, 100), emergencyPhone: str(b.emergencyPhone, 20) };
  if (!p.fullName || !p.address || !p.emergencyName || !PHONE.test(p.phone) || !PHONE.test(p.emergencyPhone) || !/^\d{4}-\d{2}-\d{2}$/.test(p.dob)) bad("Please check your details and try again");
  if (new Date(p.dob) > new Date(Date.now() - 16 * 365 * 864e5)) bad("Students must be at least 16 years old");
  if (b.photoPublicId && !String(b.photoPublicId).startsWith(`kpds/passports/${user.sub}/`)) bad("Invalid photo");
  const year = new Date().getFullYear();
  const studentId = `KPDS-${year}-${String(await nextNum(env, "students-" + year)).padStart(5, "0")}`;
  const now = iso();
  await commit(env, [
    { ...W(env, "users/" + user.sub, { role: "student", email: user.email, status: "active", createdAt: now }), currentDocument: { exists: false } },
    { ...W(env, "students/" + user.sub, { ...p, uid: user.sub, email: user.email, studentId, photoPublicId: b.photoPublicId, enrollmentStatus: "Registered", createdAt: now }), currentDocument: { exists: false } },
  ]);
  await setClaims(env, user.sub, { role: "student" });
  await notify(env, { toRole: "admin" }, "New student registration", `${p.fullName} (${studentId}) registered.`);
  await audit(env, user.sub, "student.registered", studentId);
  return { studentId };
}
async function dashboard(env, user) {
  const [st, enr, pays, notes, resps] = await Promise.all([getDoc(env, "students/" + user.sub), list(env, "enrollments", { uid: user.sub }), list(env, "payments", { uid: user.sub }), list(env, "notifications", { toUid: user.sub }, 100), list(env, "sessionResponses", { uid: user.sub }, 500)]);
  const enrollment = enr.sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0] || null;
  let sessions = [];
  if (enrollment?.status === "Active") {
    const rm = Object.fromEntries(resps.map((r) => [r.sessionId, r]));
    sessions = (await list(env, "sessions", { packageId: enrollment.packageId }, 500)).map((s) => ({ ...s, status: effStatus(s), response: rm[s.id] ? { attended: rm[s.id].attended, reason: rm[s.id].reason, at: rm[s.id].at } : null })).sort((a, b) => a.startAt.localeCompare(b.startAt));
  }
  const req = await requirements(env), counts = {};
  resps.filter((r) => r.attended === true).forEach((r) => (counts[r.sessionType] = (counts[r.sessionType] || 0) + 1));
  const total = Object.values(req).reduce((a, b) => a + b, 0);
  const done = Object.entries(req).reduce((a, [k, n]) => a + Math.min(n, counts[k] || 0), 0);
  return { student: st, enrollment, payments: pays.sort((a, b) => b.createdAt.localeCompare(a.createdAt)), sessions, notifications: notes.sort((a, b) => b.at.localeCompare(a.at)).slice(0, 50), responses: resps, progress: { total, done, breakdown: Object.entries(req).map(([type, need]) => ({ type, need, done: Math.min(need, counts[type] || 0) })) } };
}
async function enroll(env, user, b) {
  const st = await getDoc(env, "students/" + user.sub);
  if (!st) bad("Complete registration first");
  if (b.method !== "online" && b.method !== "onsite") bad("Choose a payment method");
  if (b.method === "onsite" && str(b.studentId, 30).toUpperCase() !== st.studentId) bad("That Student ID does not match your account");
  const pk = (await getPackages(env)).find((p) => p.id === b.packageId), opt = pk?.options[Number(b.optionIndex)];
  if (!pk || !opt) bad("Package not found");
  const proof = str(b.proofPublicId, 200);
  if (proof && !proof.startsWith(`kpds/proofs/${user.sub}/`)) bad("Invalid payment proof");
  if (b.method === "online" && !proof) bad("Upload your payment proof");
  const open = (await list(env, "enrollments", { uid: user.sub })).find((e) => ["Payment Verification Pending", "Active"].includes(e.status));
  if (open) bad("You already have an enrollment " + (open.status === "Active" ? "that is active" : "awaiting payment verification"), 409);
  const eid = crypto.randomUUID(), pid = crypto.randomUUID(), now = iso(), method = b.method === "online" ? "Bank Transfer" : "Paid On-Site";
  await commit(env, [
    W(env, "enrollments/" + eid, { uid: user.sub, studentId: st.studentId, studentName: st.fullName, packageId: pk.id, packageName: pk.name, optionLabel: opt.label, duration: opt.duration, price: opt.price, method, status: "Payment Verification Pending", createdAt: now }),
    W(env, "payments/" + pid, { uid: user.sub, studentId: st.studentId, studentName: st.fullName, enrollmentId: eid, packageName: pk.name, method, amount: opt.price, proofPublicId: proof, reference: str(b.reference, 80), status: "Verification Pending", createdAt: now }),
    W(env, "students/" + user.sub, { enrollmentStatus: "Payment Verification Pending" }, true),
  ]);
  await notify(env, { toRole: "admin" }, "Payment requires verification", `${st.fullName} (${st.studentId}) submitted ${method} payment for ${pk.name}.`);
  await notify(env, { toUid: user.sub }, "Payment submitted", "Your payment is awaiting verification by the school.");
  await audit(env, user.sub, "enrollment.created", eid, { pid, method });
  return { enrollmentId: eid, paymentId: pid, status: "Payment Verification Pending" };
}
async function respond(env, user, sid, b) {
  const s = await getDoc(env, "sessions/" + sid);
  if (!s) bad("Session not found", 404);
  const enr = (await list(env, "enrollments", { uid: user.sub, status: "Active" }))[0];
  if (!enr || enr.packageId !== s.packageId) bad("Not your session", 403);
  if (effStatus(s) !== "Ended") bad("This session has not ended yet");
  const rid = `${sid}_${user.sub}`;
  if (await getDoc(env, "sessionResponses/" + rid)) bad("You have already responded", 409);
  const attended = b.attended === true, reason = attended ? "" : str(b.reason, 60), note = attended ? "" : str(b.note, 300);
  if (!attended && !REASONS.includes(reason)) bad("Choose a reason");
  const st = await getDoc(env, "students/" + user.sub), at = iso();
  await put(env, "sessionResponses/" + rid, { uid: user.sub, studentId: st.studentId, studentName: st.fullName, sessionId: sid, sessionTitle: s.title, sessionType: s.type, instructorUid: s.instructorUid, instructorName: s.instructorName, packageId: s.packageId, attended, reason, note, at });
  await audit(env, user.sub, attended ? "session.attended" : "session.missed", sid, { reason });
  if (!attended) {
    const body = `Student: ${st.fullName} (${st.studentId}). Session: ${s.title}. Instructor: ${s.instructorName}. Status: Missed. Reason: ${reason}${note ? " - " + note : ""}. Submitted: ${lagosTime(at)}.`;
    await notify(env, { toRole: "admin" }, "Student missed a session", body);
    await notify(env, { toUid: s.instructorUid }, "Student missed your session", body);
    await notify(env, { toUid: user.sub }, "Missed-session report received", `We recorded that you missed "${s.title}".`);
  }
  return { ok: true };
}

// ---------- staff ----------
async function createSession(env, user, b) {
  const title = str(b.title, 100), t = (x) => /^\d{2}:\d{2}$/.test(x);
  if (!title || !TYPES.includes(b.type) || !/^\d{4}-\d{2}-\d{2}$/.test(b.date) || !t(b.start) || !t(b.end) || b.end <= b.start) bad("Check the session details");
  const startAt = new Date(`${b.date}T${b.start}:00+01:00`).toISOString(), endAt = new Date(`${b.date}T${b.end}:00+01:00`).toISOString(); // times entered in Lagos time (WAT)
  const iUid = user.role === "admin" ? str(b.instructorUid, 128) : user.sub, ins = iUid && (await getDoc(env, "instructors/" + iUid));
  if (!ins || ins.status !== "active") bad("Choose an active instructor");
  if (!(await getPackages(env)).some((p) => p.id === b.packageId)) bad("Choose a package");
  const link = str(b.meetingLink, 300);
  if (link && !/^https:\/\/\S+$/.test(link)) bad("Meeting link must start with https://");
  const id = crypto.randomUUID();
  await put(env, "sessions/" + id, { title, type: b.type, startAt, endAt, instructorUid: iUid, instructorName: ins.fullName, packageId: b.packageId, meetingLink: link, location: str(b.location, 200), status: "Scheduled", createdBy: user.sub, createdAt: iso() });
  await audit(env, user.sub, "session.created", id, { title });
  const when = `${b.date} ${b.start}-${b.end}`;
  await notifyPackage(env, b.packageId, "New session scheduled", `${title} on ${when} with ${ins.fullName}.`);
  if (iUid !== user.sub) await notify(env, { toUid: iUid }, "New session assigned", `${title} on ${when}.`);
  if (user.role === "instructor") await notify(env, { toRole: "admin" }, "Instructor created a session", `${ins.fullName} created "${title}" on ${when}.`);
  return { id };
}
async function endSession(env, user, sid) {
  const s = await getDoc(env, "sessions/" + sid);
  if (!s || (user.role === "instructor" && s.instructorUid !== user.sub)) bad("Session not found", 404);
  const now = iso();
  if (effStatus(s, now) !== "Started") bad("Only a session in progress can be ended");
  await patch(env, "sessions/" + sid, { status: "Ended", endedAt: now, endedEarly: now < s.endAt });
  await audit(env, user.sub, "session.ended.manual", sid, { early: now < s.endAt });
  await notifyPackage(env, s.packageId, "Session ended", `"${s.title}" has ended. Please confirm whether you attended.`);
  return { ok: true };
}
async function decidePayment(env, user, pid, b) {
  const p = await getDoc(env, "payments/" + pid);
  if (!p) bad("Payment not found", 404);
  if (p.status !== "Verification Pending") bad("Already decided", 409);
  const ok = b.approve === true, now = iso(), note = str(b.note, 300);
  await commit(env, [
    W(env, "payments/" + pid, { status: ok ? "Confirmed" : "Rejected", decidedBy: user.sub, decidedAt: now, note }, true),
    W(env, "enrollments/" + p.enrollmentId, { status: ok ? "Active" : "Cancelled", ...(ok ? { activatedAt: now } : {}) }, true),
    W(env, "students/" + p.uid, { enrollmentStatus: ok ? "Enrolled/Active" : "Registered" }, true),
  ]);
  await notify(env, { toUid: p.uid }, ok ? "Payment approved" : "Payment rejected", ok ? "Your enrollment is now active. Check your sessions and timetable." : `Your payment was rejected.${note ? " Reason: " + note : ""} You can enroll again.`);
  await audit(env, user.sub, ok ? "payment.confirmed" : "payment.rejected", pid, { note });
  return { ok: true };
}
async function recordOnsite(env, user, b) {
  const st = (await list(env, "students", { studentId: str(b.studentId, 30).toUpperCase() }))[0];
  if (!st) bad("Student ID not found", 404);
  const pk = (await getPackages(env)).find((p) => p.id === b.packageId), opt = pk?.options[Number(b.optionIndex)];
  if (!opt) bad("Package not found");
  if ((await list(env, "enrollments", { uid: st.uid })).some((e) => ["Payment Verification Pending", "Active"].includes(e.status))) bad("Student already has an open enrollment", 409);
  const eid = crypto.randomUUID(), pid = crypto.randomUUID(), now = iso(), amount = Number(b.amount) || opt.price;
  await commit(env, [
    W(env, "enrollments/" + eid, { uid: st.uid, studentId: st.studentId, studentName: st.fullName, packageId: pk.id, packageName: pk.name, optionLabel: opt.label, duration: opt.duration, price: opt.price, method: "Paid On-Site", status: "Active", createdAt: now, activatedAt: now }),
    W(env, "payments/" + pid, { uid: st.uid, studentId: st.studentId, studentName: st.fullName, enrollmentId: eid, packageName: pk.name, method: "Paid On-Site", amount, status: "Confirmed", paidOn: str(b.date, 10), note: str(b.note, 300), recordedBy: user.sub, createdAt: now }),
    W(env, "students/" + st.uid, { enrollmentStatus: "Enrolled/Active" }, true),
  ]);
  await notify(env, { toUid: st.uid }, "Enrollment active", "The school recorded your on-site payment. Your enrollment is active.");
  await audit(env, user.sub, "payment.recorded.onsite", pid, { studentId: st.studentId, amount });
  return { ok: true };
}
async function createInstructor(env, user, b) {
  const fullName = str(b.fullName, 100), email = str(b.email, 120).toLowerCase(), phone = str(b.phone, 20), type = ["Online Instructor", "Practical/Off-site Instructor", "Hybrid Instructor"].includes(b.type) ? b.type : "";
  if (!fullName || !/^\S+@\S+\.\S+$/.test(email) || !PHONE.test(phone) || !type) bad("Check the instructor details");
  const a = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789", tmp = Array.from(crypto.getRandomValues(new Uint8Array(12)), (x) => a[x % a.length]).join("") + "!7";
  const uid = await createAuthUser(env, email, tmp, fullName);
  const instructorId = `KPDS-INS-${String(await nextNum(env, "instructors")).padStart(3, "0")}`, now = iso();
  await setClaims(env, uid, { role: "instructor", mcp: true });
  await commit(env, [W(env, "users/" + uid, { role: "instructor", email, status: "active", createdAt: now }), W(env, "instructors/" + uid, { uid, instructorId, fullName, email, phone, type, status: "active", createdAt: now })]);
  await audit(env, user.sub, "instructor.created", uid, { instructorId });
  return { instructorId, email, tempPassword: tmp }; // shown once; instructor must change it at first login
}
async function bootstrap(env, b) {
  if (!env.BOOTSTRAP_KEY || b.key !== env.BOOTSTRAP_KEY) bad("Not found", 404);
  const email = str(b.email, 120).toLowerCase(), pw = String(b.password || "");
  if (!/^\S+@\S+\.\S+$/.test(email) || pw.length < 10) bad("Email and a password of 10+ characters required");
  const uid = await createAuthUser(env, email, pw, str(b.name, 100) || "Administrator");
  await setClaims(env, uid, { role: "admin" });
  await put(env, "users/" + uid, { role: "admin", email, status: "active", createdAt: iso() });
  return { ok: true, note: "Admin created. Remove the BOOTSTRAP_KEY secret now." };
}
async function overview(env, user) {
  const now = iso(), today = lagosDay(now);
  if (user.role === "instructor") {
    const [ss, miss] = await Promise.all([list(env, "sessions", { instructorUid: user.sub }, 500), list(env, "sessionResponses", { instructorUid: user.sub, attended: false }, 50)]);
    const s = ss.map((x) => ({ ...x, status: effStatus(x) }));
    return { today: s.filter((x) => lagosDay(x.startAt) === today), upcoming: s.filter((x) => x.status === "Scheduled").slice(0, 10), missed: miss };
  }
  const [students, enrActive, pays, ss, miss, ins, vid, notes, logs] = await Promise.all([list(env, "students", {}, 1000), list(env, "enrollments", { status: "Active" }, 1000), list(env, "payments", { status: "Verification Pending" }, 200), list(env, "sessions", {}, 500), list(env, "sessionResponses", { attended: false }, 100), list(env, "instructors", { status: "active" }), Promise.resolve([]), list(env, "notifications", { toRole: "admin" }, 100), list(env, "auditLogs", {}, 15, "at")]);
  const s = ss.map((x) => ({ ...x, status: effStatus(x) }));
  return { counts: { students: students.length, active: enrActive.length, pendingPayments: pays.length, todaySessions: s.filter((x) => lagosDay(x.startAt) === today).length, upcomingSessions: s.filter((x) => x.status === "Scheduled").length, missed: miss.length, instructors: ins.length }, missed: miss.sort((a, b) => b.at.localeCompare(a.at)).slice(0, 10), notifications: notes.sort((a, b) => b.at.localeCompare(a.at)).slice(0, 8), activity: logs };
}

async function route(req, env, url) {
  const parts = url.pathname.split("/").filter(Boolean), m = req.method, a = parts[0], b2 = parts[1], b3 = parts[2], b4 = parts[3];
  if (m === "GET" && a === "packages") return getPackages(env);
  if (m === "GET" && a === "locations") return list(env, "locations");
  if (m === "GET" && a === "instructors") return (await list(env, "instructors", { status: "active" })).map((i) => ({ name: i.fullName, type: i.type }));
  if (m === "GET" && a === "settings") { const s = (await getDoc(env, "settings/school")) || {}; return { phone: s.phone, email: s.email, whatsapp: s.whatsapp }; }
  const body = m === "POST" ? await req.json().catch(() => ({})) : {};
  if (m === "POST" && a === "bootstrap") return bootstrap(env, body);
  const user = await verifyIdToken((req.headers.get("Authorization") || "").replace(/^Bearer /, ""), env);

  if (a === "students" && b2 === "register" && m === "POST") return registerStudent(env, user, body);
  if (a === "uploads" && m === "POST") {
    if (user.role && user.role !== "student") bad("Forbidden", 403);
    const kind = body.purpose === "proof" ? "proofs" : "passports", folder = `kpds/${kind}/${user.sub}`, timestamp = Math.floor(Date.now() / 1000), type = "authenticated";
    const hex = [...new Uint8Array(await crypto.subtle.digest("SHA-1", enc.encode(`folder=${folder}&timestamp=${timestamp}&type=${type}${env.CLOUDINARY_API_SECRET}`)))].map((x) => x.toString(16).padStart(2, "0")).join("");
    return { cloudName: env.CLOUDINARY_CLOUD, apiKey: env.CLOUDINARY_API_KEY, folder, timestamp, type, signature: hex };
  }
  if (a === "me" && !b2) {
    const u = await getDoc(env, "users/" + user.sub), role = user.role || u?.role || null;
    const st = role === "student" ? await getDoc(env, "students/" + user.sub) : null;
    return { role, status: u?.status || null, studentId: st?.studentId || null, fullName: st?.fullName || null, mustChangePassword: !!user.mcp };
  }
  if (a === "me" && b2 === "password-changed" && m === "POST") {
    await gateStaff(env, user);
    if (!user.mcp) return { ok: true };
    const r = await fetch(ITK(env) + "/accounts:lookup", { method: "POST", headers: await H(env), body: JSON.stringify({ localId: [user.sub] }) });
    const u = (await r.json()).users?.[0];
    if (!u || !(Number(u.passwordUpdatedAt) > Number(u.createdAt) + 2000)) bad("Password has not been changed yet");
    await setClaims(env, user.sub, { role: user.role });
    await audit(env, user.sub, "instructor.password_changed", user.sub);
    return { ok: true };
  }

  if (a === "bank") { await gateStudent(env, user); const s = (await getDoc(env, "settings/school")) || {}; return { bankName: s.bankName, accountName: s.accountName, accountNumber: s.accountNumber }; }
  if (a === "student") { await gateStudent(env, user); if (b2 === "dashboard") return dashboard(env, user); }
  if (a === "enrollments" && m === "POST") { await gateStudent(env, user); return enroll(env, user, body); }
  if (a === "sessions" && b3 === "respond" && m === "POST") { await gateStudent(env, user); return respond(env, user, b2, body); }
  if (a === "notifications" && b2 === "read" && m === "POST") {
    const u = await getDoc(env, "users/" + user.sub), staffAdmin = user.role === "admin";
    const n = (await list(env, "notifications", staffAdmin ? { toRole: "admin" } : { toUid: user.sub }, 100)).filter((x) => x.read === false).slice(0, 50);
    await Promise.all(n.map((x) => patch(env, "notifications/" + x.id, { read: true })));
    return { ok: true };
  }

  if (a === "admin") {
    await gateStaff(env, user, ["payments", "students", "instructors", "packages", "settings", "locations"].includes(b2));
    if (b2 === "overview") return overview(env, user);
    if (b2 === "notifications") return (await list(env, "notifications", user.role === "admin" ? { toRole: "admin" } : { toUid: user.sub }, 100)).sort((x, y) => y.at.localeCompare(x.at));
    if (b2 === "sessions") {
      if (m === "POST" && b3 === "create") return createSession(env, user, body);
      if (m === "POST" && b4 === "end") return endSession(env, user, b3);
      const where = user.role === "admin" ? {} : { instructorUid: user.sub };
      const [ss, rs] = await Promise.all([list(env, "sessions", where, 500), list(env, "sessionResponses", where, 1000)]);
      return ss.map((s) => ({ ...s, status: effStatus(s), attended: rs.filter((r) => r.sessionId === s.id && r.attended === true).length, missed: rs.filter((r) => r.sessionId === s.id && r.attended === false).length })).sort((x, y) => y.startAt.localeCompare(x.startAt));
    }
    if (b2 === "payments") {
      if (m === "POST" && b3 === "record") return recordOnsite(env, user, body);
      if (m === "POST" && b4 === "decision") return decidePayment(env, user, b3, body);
      const ps = (await list(env, "payments", {}, 500)).sort((x, y) => y.createdAt.localeCompare(x.createdAt));
      return Promise.all(ps.map(async (p) => ({ ...p, proofUrl: await proofUrl(env, p.proofPublicId) })));
    }
    if (b2 === "students") {
      const q = (url.searchParams.get("q") || "").toLowerCase();
      const all = await list(env, "students", {}, 1000), enr = await list(env, "enrollments", {}, 1000);
      return all.filter((s) => !q || [s.studentId, s.fullName, s.email, s.phone].some((v) => String(v || "").toLowerCase().includes(q)) || enr.some((e) => e.uid === s.uid && e.id.startsWith(q))).slice(0, 100).map((s) => ({ ...s, enrollments: enr.filter((e) => e.uid === s.uid).map((e) => ({ id: e.id, package: e.packageName, status: e.status })) }));
    }
    if (b2 === "instructors") {
      if (m === "POST" && !b3) return createInstructor(env, user, body);
      if (m === "POST" && b4 === "status") {
        const st = body.status === "suspended" ? "suspended" : "active";
        await commit(env, [W(env, "users/" + b3, { status: st }, true), W(env, "instructors/" + b3, { status: st }, true)]);
        await authUpdate(env, { localId: b3, disableUser: st === "suspended" });
        await audit(env, user.sub, "instructor." + st, b3);
        return { ok: true };
      }
      return list(env, "instructors", {}, 200);
    }
    if (b2 === "packages") {
      if (m === "POST") {
        const pk = Array.isArray(body.packages) ? body.packages : bad("Invalid packages");
        await commit(env, pk.map((p, i) => {
          const id = str(p.id, 40).replace(/[^a-z0-9-]/gi, ""), opts = (p.options || []).map((o) => ({ label: str(o.label, 80), duration: str(o.duration, 40), price: Number(o.price) }));
          if (!id || !str(p.name, 80) || !opts.length || opts.some((o) => !o.label || !(o.price >= 0))) bad("Check package " + (i + 1));
          return W(env, "packages/" + id, { name: str(p.name, 80), desc: str(p.desc, 300), options: JSON.stringify(opts), active: p.active !== false, order: i });
        }));
        await audit(env, user.sub, "packages.updated", "packages");
        return { ok: true };
      }
      return getPackages(env);
    }
    if (b2 === "settings") {
      if (m === "POST") {
        let req = str(body.requirements, 600);
        if (req) { try { const o = JSON.parse(req); if (Object.values(o).some((n) => !Number.isInteger(n) || n < 0)) throw 0; } catch { bad("Requirements must be JSON like {\"Online Theory\":8}"); } }
        await patch(env, "settings/school", { phone: str(body.phone, 30), email: str(body.email, 120), whatsapp: str(body.whatsapp, 30), bankName: str(body.bankName, 80), accountName: str(body.accountName, 120), accountNumber: str(body.accountNumber, 20), requirements: req });
        await audit(env, user.sub, "settings.updated", "settings/school");
        return { ok: true };
      }
      return { ...((await getDoc(env, "settings/school")) || {}), requirements: (await getDoc(env, "settings/school"))?.requirements || JSON.stringify(DEFAULT_REQ) };
    }
    if (b2 === "locations") {
      if (m === "POST" && b4 === "delete") { await del(env, "locations/" + b3); return { ok: true }; }
      if (m === "POST") {
        const l = { name: str(body.name, 100), address: str(body.address, 250), hours: str(body.hours, 100), phone: str(body.phone, 30), mapUrl: /^https:\/\/\S+$/.test(body.mapUrl || "") ? body.mapUrl : "" };
        if (!l.name || !l.address) bad("Name and address required");
        await put(env, "locations/" + crypto.randomUUID(), l);
        return { ok: true };
      }
      return list(env, "locations");
    }
  }
  bad("Not found", 404);
}

async function tick(env) {
  const now = iso();
  for (const st of ["Scheduled", "Started"]) {
    for (const s of await list(env, "sessions", { status: st }, 500)) {
      let next = null;
      if (now >= s.endAt) next = "Ended"; else if (st === "Scheduled" && now >= s.startAt) next = "Started";
      if (!next) continue;
      await patch(env, "sessions/" + s.id, { status: next, ...(next === "Started" ? { startedAt: now } : { endedAt: now, ...(s.startedAt ? {} : { startedAt: s.startAt }) }), autoChanged: true });
      await audit(env, "system", next === "Started" ? "session.started.auto" : "session.ended.auto", s.id);
      if (next === "Started") await notifyPackage(env, s.packageId, "Session started", `"${s.title}" has started.`);
      else await notifyPackage(env, s.packageId, "Session ended", `"${s.title}" has ended. Please confirm whether you attended.`);
    }
  }
}

export default {
  async fetch(req, env) {
    const origins = (env.ALLOWED_ORIGIN || "").split(",").map((x) => x.trim()), o = req.headers.get("Origin");
    const cors = { "Access-Control-Allow-Origin": origins.includes(o) ? o : origins[0], "Access-Control-Allow-Headers": "Authorization, Content-Type", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", Vary: "Origin" };
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    try { return J(await route(req, env, new URL(req.url)), 200, cors); }
    catch (e) { return J({ error: e instanceof HttpError ? e.message : "Server error" }, e.status || 500, cors); }
  },
  async scheduled(_e, env, ctx) { ctx.waitUntil(tick(env)); }, // status automation runs on the server every minute
};
