import api, { setAccessToken } from "./api";

export async function login(email, password) {
  const { data } = await api.post("/auth/login", { email, password });
  setAccessToken(data.access_token);
  return data.user;
}

export async function logout() {
  await api.post("/auth/logout");
  setAccessToken(null);
}

export async function restoreSession() {
  const { data } = await api.post("/auth/refresh");
  setAccessToken(data.access_token);
  return data.user;
}
