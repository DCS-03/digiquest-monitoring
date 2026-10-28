"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2, ShieldCheck } from "lucide-react";
import { login } from "@/services/auth.service";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function onSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const user = await login(email, password);
      router.push(user.role === "employee" ? "/employee/dashboard" : "/admin/dashboard");
    } catch (err) {
      setError(err.response?.status === 429 ? "Too many attempts. Try again shortly." : "Invalid email or password.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-900 p-4">
      <form onSubmit={onSubmit} className="w-full max-w-sm space-y-4 rounded-xl bg-white p-8 shadow-xl">
        <div className="flex items-center gap-2 text-emerald-600">
          <ShieldCheck size={28} />
          <h1 className="text-xl font-semibold text-slate-900">DigiQuest Monitoring</h1>
        </div>
        <p className="text-sm text-slate-500">
          Activity on company devices is monitored per company policy. Sign in to view your records.
        </p>
        <label className="block text-sm font-medium">Work email
          <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)}
            className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 focus:border-emerald-500 focus:outline-none" />
        </label>
        <label className="block text-sm font-medium">Password
          <input type="password" required value={password} onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 focus:border-emerald-500 focus:outline-none" />
        </label>
        {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
        <button disabled={loading}
          className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-600 py-2 font-medium text-white hover:bg-emerald-700 disabled:opacity-60">
          {loading && <Loader2 className="animate-spin" size={16} />} Sign in
        </button>
      </form>
    </main>
  );
}
