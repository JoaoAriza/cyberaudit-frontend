import axios from "axios";

console.log("DEPLOY VERSION: ", "timeout-120-v1");

export const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL ?? "http://localhost:8080",
    timeout: 120000,
});