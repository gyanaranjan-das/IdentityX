import { useState } from "react";
import api from "../services/api.js";
import { Link, useNavigate } from "react-router-dom";
export default function Register() {
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");

    const handleRegister = async (e) => {
    e.preventDefault();
    try {
      await api.post("/auth/register", { email, password });
      alert("Registered successfully");
    } catch (err) {
alert(err.response?.data?.message || "Registration failed");
    }
  };

  return(
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
    <form onSubmit={handleRegister}
     className="
     bg-white
     p-10
     rounded-2xl
     shadow-gray-200/60
     max-w-md
     w-full
     space-y-6
     ">
        <h2 className="
        text-2xl 
        font-semibold
        tracking-tight
        text-center
        text-gray-900">Create Account</h2>
        <div className="
        space-y-4">
        <input type="Email"
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
        "/>
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
        focus:ring-2 focus:ring-black
        "
      /></div>
      <button type="submit"
      className="
      w-full
      bg-black text-white
      py-2
      rounded-lg
      hover:bg-gray-800
      active:scale-95
      transition-all duration-200
      focus:outline-none
      focus:ring-2 focus:ring-black
      focus:ring-offset-2">Register</button>
      <p className="text-center text-sm text-gray-600">Already have an account? {" "}
        <Link to="/login" className="text-black font-medium hover:underline">Login</Link>
      </p>
    </form>
    </div>
  )
}