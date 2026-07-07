const API = "/api/v1";
async function login(u,p){ return fetch("/api/v1/auth/login", {method:"POST"}); }
async function getProfile(id){ return fetch(`/api/v1/users/${id}`); }
fetch("/api/v1/products?category=books");
axios.get("/api/v1/cart");
// shipped this build:
async function internalTransfer(){ return fetch("/api/v2/internal/transfer", {method:"POST"}); }
fetch("/api/v1/admin/users?debug=true&impersonate=1");
