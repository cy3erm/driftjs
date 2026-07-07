const API = "/api/v1";
async function login(u,p){ return fetch("/api/v1/auth/login", {method:"POST"}); }
async function getProfile(id){ return fetch(`/api/v1/users/${id}`); }
fetch("/api/v1/products?category=books");
axios.get("/api/v1/cart");
