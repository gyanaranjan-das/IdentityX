import { useState } from "react";
import api from "../services/api";
import { useNavigate,Link } from "react-router-dom";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const res = await api.post("/auth/login", { email, password });
      localStorage.setItem("token", res.data.token);
      navigate("/dashboard");
    } catch (err) {
      alert(err.response?.data?.message || "Login failed");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
    <form onSubmit={handleLogin}
    className="
    bg-white 
    p-10
    rounded-2xl 
    shadow-xl
    shadow-gray-200/60 
    w-full 
    max-w-md 
    space-y-6">
      <h2 className="
      text-2xl
      font-semibold 
      tracking-tight
      text-center
       text-gray-900"
       >Login</h2>

       <div className="space-y-4">
      <input
        type="email"
        placeholder="Email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        className="
        w-full
        px-4 py-2
        border border-gray-300
        rounded-lg
        focus:outline-none
        focus:ring-2 focus:ring-black
        "
      />
      <input
        placeholder="Password"
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        className="
        w-full
        px-4 py-2
        border border-gray-300
        rounded-lg
        focus:outline-none
        focus:ring-2
        focus:ring-black
        "
      />
      </div>
      <button type="submit"
      className="
      w-full
      bg-black
      text-white
      py-2
      rounded-lg
      hover:bg-gray-800
      active:scale-95
      transition-all duration-200
      focus:outline-none
      focus:ring-2 focus:ring-black focus:ring-offset-2">Login</button>
      <p className="text-center text-sm text-gray-600">Don't have an account?{" "}
        <Link to="/register"
        className="text-black font-medium hover:underline">
           Register
        </Link>
      </p>
    </form>
    </div>
  );
}
