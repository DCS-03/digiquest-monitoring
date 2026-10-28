// The browser only talks to this Next.js origin; /api/v1/* is proxied to the FastAPI
// backend server-side. That keeps the httpOnly refresh cookie first-party (SameSite=Strict works)
// and avoids CORS. BACKEND_URL is server-only (not exposed to the browser).
const raw = process.env.BACKEND_URL || "http://localhost:8000";
// Render's internal host:port has no scheme.
const backend = /^https?:\/\//.test(raw) ? raw : `http://${raw}`;

const nextConfig = {
  async rewrites() {
    return [{ source: "/api/v1/:path*", destination: `${backend}/api/v1/:path*` }];
  },
};
export default nextConfig;
