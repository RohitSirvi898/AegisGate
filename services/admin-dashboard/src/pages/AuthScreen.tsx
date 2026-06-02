import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Key, Mail, Lock, RefreshCw, AlertTriangle, ArrowRight } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function AuthScreen() {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) {
      setError('Please fill in all security fields.');
      return;
    }

    setLoading(true);
    setError(null);

    const endpoint = isLogin ? '/api/v1/auth/login' : '/api/v1/auth/register';
    const apiURL = `${import.meta.env.VITE_API_BASE_URL}${endpoint}`;

    try {
      const response = await fetch(apiURL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email: email.trim(),
          password: password.trim()
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || `HTTP error ${response.status}`);
      }

      if (data.token) {
        login(data.token);
        navigate('/dashboard');
      } else {
        throw new Error('Authentication token not received.');
      }
    } catch (err: any) {
      console.error('❌ Authentication Failure:', err);
      setError(err.message || 'Identity verification failed. Connection timeout.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070b13] text-slate-100 flex items-center justify-center font-mono relative overflow-hidden px-4">
      {/* Cybersecurity scanline background mesh */}
      <div className="absolute inset-0 pointer-events-none opacity-5 bg-[linear-gradient(rgba(18,24,38,0.8)_50%,rgba(11,15,25,0.8)_50%)] bg-[length:100%_4px]"></div>

      {/* Cybernetic glowing background grids */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-emerald-600/5 rounded-full blur-3xl pointer-events-none"></div>

      <div className="w-full max-w-md bg-[#0c121e]/80 border border-slate-800 rounded-2xl shadow-2xl p-8 relative z-10 backdrop-blur-md">
        
        {/* Glowing cyber border */}
        <div className="absolute inset-0 rounded-2xl border border-emerald-500/20 pointer-events-none"></div>

        {/* Brand Header */}
        <div className="flex flex-col items-center mb-8">
          <div className="bg-emerald-500/10 p-3.5 rounded-xl border border-emerald-500/35 mb-3.5 shadow-[0_0_15px_rgba(16,185,129,0.15)]">
            <Shield className="w-8 h-8 text-emerald-400" />
          </div>
          <h1 className="text-2xl font-bold tracking-wider text-emerald-400 flex items-center gap-2">
            AEGIS<span className="text-slate-100 font-semibold">GATE</span>
          </h1>
          <p className="text-[10px] text-slate-400 tracking-widest uppercase mt-1">Identity & Access Management (IAM)</p>
        </div>

        {/* Tab Selector */}
        <div className="grid grid-cols-2 gap-2 bg-[#05080f] p-1.5 rounded-lg border border-slate-800/60 mb-6 text-xs">
          <button
            type="button"
            onClick={() => { setIsLogin(true); setError(null); }}
            className={`py-2 rounded font-bold uppercase tracking-wider transition-all duration-200 cursor-pointer ${
              isLogin 
                ? 'text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 shadow-inner'
                : 'text-slate-400 hover:text-slate-200 border border-transparent'
            }`}
          >
            Security Login
          </button>
          <button
            type="button"
            onClick={() => { setIsLogin(false); setError(null); }}
            className={`py-2 rounded font-bold uppercase tracking-wider transition-all duration-200 cursor-pointer ${
              !isLogin 
                ? 'text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 shadow-inner'
                : 'text-slate-400 hover:text-slate-200 border border-transparent'
            }`}
          >
            Create Account
          </button>
        </div>

        {/* Form Block */}
        <form onSubmit={handleSubmit} className="space-y-5">
          
          <div className="space-y-2">
            <label className="text-[10px] text-slate-400 uppercase tracking-widest block font-bold">Email Address</label>
            <div className="relative">
              <Mail className="absolute left-3 top-3.5 w-4 h-4 text-slate-500" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="developer@aegisgate.io"
                required
                className="w-full bg-slate-900 border border-slate-800 focus:border-emerald-500/50 rounded-lg pl-10 pr-4 py-3 text-slate-100 placeholder-slate-600 text-sm focus:outline-none transition duration-200 font-mono"
              />
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-[10px] text-slate-400 uppercase tracking-widest block font-bold">Access Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-3.5 w-4 h-4 text-slate-500" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                className="w-full bg-slate-900 border border-slate-800 focus:border-emerald-500/50 rounded-lg pl-10 pr-4 py-3 text-slate-100 placeholder-slate-600 text-sm focus:outline-none transition duration-200 font-mono"
              />
            </div>
          </div>

          {error && (
            <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 px-3.5 py-3 rounded-lg font-semibold flex items-start gap-2.5 leading-relaxed">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-emerald-500/10 hover:bg-emerald-500/20 disabled:opacity-50 text-emerald-400 font-bold uppercase text-xs tracking-widest border border-emerald-500/35 shadow-[0_0_10px_rgba(16,185,129,0.1)] rounded-lg py-3.5 transition duration-200 flex items-center justify-center gap-2 cursor-pointer disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-emerald-400" />
                <span>Decrypting Handshake...</span>
              </>
            ) : (
              <>
                <Key className="w-4 h-4" />
                <span>{isLogin ? 'Establish Secure Connection' : 'Register Secure Credentials'}</span>
                <ArrowRight className="w-4 h-4 text-emerald-400/50" />
              </>
            )}
          </button>

        </form>

        {/* Footer */}
        <div className="mt-8 text-center text-[9px] text-slate-600 uppercase tracking-widest border-t border-slate-800/80 pt-4">
          <span>AES-256 Symmetric Identity Token Ingress</span>
        </div>

      </div>
    </div>
  );
}
